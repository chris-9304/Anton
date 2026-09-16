//! Owlyshield-like behavioral analysis: process families, directory clustering, coordinated entropy.
//! Detects ransomware that spawns multiple children to encrypt files in parallel.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

const ACTIVITY_WINDOW_CAP: usize = 50;
const TRAVERSAL_WINDOW_SECS: f64 = 1.0;
const TRAVERSAL_DIFFERENT_SUBFOLDERS_RATIO: f32 = 0.8;
const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;
const RAMP_UP_RECENT: usize = 10;
const RAMP_UP_OLDER: usize = 20;
// Refreshing the full OS process table on every single file event is expensive; cap
// how often resolve_root_pid actually rescans, and reuse the last-known result between
// refreshes (safe: the events we're resolving arrive far more often than processes
// realistically reparent).
const PROCESS_REFRESH_INTERVAL: Duration = Duration::from_millis(500);

/// Operation type for file activity (maps from watcher event types).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOp {
    Open,
    Read,
    Write,
    Create,
    Delete,
}

/// A single entry in the activity ring buffer.
#[derive(Clone, Debug)]
pub struct ActivityEntry {
    pub timestamp: SystemTime,
    pub op: FileOp,
    pub file_path: std::path::PathBuf,
    pub entropy: f64,
}

/// Process family: root PID plus all descendant PIDs and a shared activity window.
#[derive(Debug)]
pub struct ProcessFamily {
    pub root_pid: u32,
    pub member_pids: HashSet<u32>,
    pub activity_window: VecDeque<ActivityEntry>,
}

impl ProcessFamily {
    fn new(root_pid: u32) -> Self {
        let mut member_pids = HashSet::new();
        member_pids.insert(root_pid);
        Self {
            root_pid,
            member_pids,
            activity_window: VecDeque::with_capacity(ACTIVITY_WINDOW_CAP),
        }
    }

    fn push_activity(&mut self, entry: ActivityEntry) {
        if self.activity_window.len() >= ACTIVITY_WINDOW_CAP {
            self.activity_window.pop_front();
        }
        self.activity_window.push_back(entry);
    }

    /// Directory clustering: >80% of ops in different subfolders of same root within 1 second -> high score.
    fn traversal_score(&self) -> f32 {
        if self.activity_window.len() < 2 {
            return 0.0;
        }
        let now = self.activity_window.back().map(|e| e.timestamp).unwrap_or_else(SystemTime::now);
        let window = Duration::from_secs_f64(TRAVERSAL_WINDOW_SECS);
        let mut subfolders: HashSet<String> = HashSet::new();
        let mut count_in_window = 0usize;
        for e in self.activity_window.iter().rev() {
            if now.duration_since(e.timestamp).unwrap_or_default() > window {
                break;
            }
            count_in_window += 1;
            let parent = e.file_path.parent();
            let sub = parent
                .and_then(|p| p.to_str())
                .unwrap_or("")
                .to_string();
            if !sub.is_empty() {
                subfolders.insert(sub);
            }
        }
        if count_in_window < 2 {
            return 0.0;
        }
        let ratio = subfolders.len() as f32 / count_in_window as f32;
        if ratio >= TRAVERSAL_DIFFERENT_SUBFOLDERS_RATIO {
            (ratio - TRAVERSAL_DIFFERENT_SUBFOLDERS_RATIO) / (1.0 - TRAVERSAL_DIFFERENT_SUBFOLDERS_RATIO).max(0.01)
        } else {
            ratio / TRAVERSAL_DIFFERENT_SUBFOLDERS_RATIO
        }
        .clamp(0.0, 1.0)
    }

    /// Coordinated entropy: fraction of ops with high entropy (summed across all member PIDs).
    fn entropy_trend(&self) -> f32 {
        if self.activity_window.is_empty() {
            return 0.0;
        }
        let high = self
            .activity_window
            .iter()
            .filter(|e| e.entropy > HIGH_ENTROPY_THRESHOLD)
            .count();
        (high as f32 / self.activity_window.len().max(1) as f32).clamp(0.0, 1.0)
    }

    /// Ramp-up: recent Open+Read+Write rate vs older rate (novelty detection).
    fn ramp_up_score(&self) -> f32 {
        if self.activity_window.len() < RAMP_UP_OLDER + RAMP_UP_RECENT {
            return 0.0;
        }
        let ops: Vec<&ActivityEntry> = self.activity_window.iter().collect();
        let n = ops.len();
        let recent: Vec<_> = ops[n.saturating_sub(RAMP_UP_RECENT)..].to_vec();
        let older: Vec<_> = ops[n.saturating_sub(RAMP_UP_RECENT + RAMP_UP_OLDER)..n.saturating_sub(RAMP_UP_RECENT)].to_vec();
        if older.is_empty() {
            return if recent.len() >= 5 { 0.5 } else { 0.0 };
        }
        let recent_io = recent
            .iter()
            .filter(|e| matches!(e.op, FileOp::Open | FileOp::Read | FileOp::Write))
            .count();
        let older_io = older
            .iter()
            .filter(|e| matches!(e.op, FileOp::Open | FileOp::Read | FileOp::Write))
            .count();
        let recent_rate = recent_io as f32 / RAMP_UP_RECENT as f32;
        let older_rate = older_io as f32 / older.len() as f32;
        if older_rate <= 0.0 {
            return recent_rate.min(1.0);
        }
        let ratio = recent_rate / older_rate;
        (ratio.min(10.0) / 10.0).clamp(0.0, 1.0)
    }
}

/// Scores returned after updating a process family.
#[derive(Clone, Copy, Debug, Default)]
pub struct FamilyScore {
    pub traversal_score: f32,
    pub entropy_trend: f32,
    pub ramp_up_score: f32,
}

/// Behavior engine: maps root_pid -> ProcessFamily, uses sysinfo to resolve parent chain.
pub struct BehaviorEngine {
    families: HashMap<u32, ProcessFamily>,
    system: sysinfo::System,
    last_refresh: Instant,
}

impl BehaviorEngine {
    pub fn new() -> Self {
        Self {
            families: HashMap::new(),
            system: sysinfo::System::new_all(),
            // Already "expired" so the first call still refreshes.
            last_refresh: Instant::now() - PROCESS_REFRESH_INTERVAL,
        }
    }

    /// Resolve root PID by walking parent chain via sysinfo. If pid is unknown, use pid as root.
    /// The process table is only rescanned at most every PROCESS_REFRESH_INTERVAL --
    /// scanning it on every single file event is a major bottleneck under real event load.
    pub fn resolve_root_pid(&mut self, pid: u32) -> u32 {
        let now = Instant::now();
        if now.duration_since(self.last_refresh) > PROCESS_REFRESH_INTERVAL {
            self.system.refresh_processes();
            self.last_refresh = now;
        }
        let mut current = sysinfo::Pid::from_u32(pid);
        let mut visited = HashSet::new();
        while visited.insert(current.as_u32()) {
            if let Some(proc_) = self.system.process(current) {
                match proc_.parent() {
                    Some(parent) => current = parent,
                    None => return current.as_u32(),
                }
            } else {
                return pid;
            }
        }
        pid
    }

    /// Record a file operation and return the family scores for the process family.
    pub fn update(
        &mut self,
        pid: u32,
        path: &Path,
        entropy: f64,
        op: FileOp,
    ) -> FamilyScore {
        let root_pid = self.resolve_root_pid(pid);
        let family = self
            .families
            .entry(root_pid)
            .or_insert_with(|| ProcessFamily::new(root_pid));
        family.member_pids.insert(pid);
        let entry = ActivityEntry {
            timestamp: SystemTime::now(),
            op,
            file_path: path.to_path_buf(),
            entropy,
        };
        family.push_activity(entry);

        FamilyScore {
            traversal_score: family.traversal_score(),
            entropy_trend: family.entropy_trend(),
            ramp_up_score: family.ramp_up_score(),
        }
    }
}

impl Default for BehaviorEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Map from EventType (from watcher) to FileOp for the behavior engine.
pub fn event_type_to_file_op(event_type: crate::models::EventType) -> FileOp {
    use crate::models::EventType;
    match event_type {
        EventType::Created => FileOp::Create,
        EventType::Modified => FileOp::Write,
        EventType::Deleted => FileOp::Delete,
        EventType::Moved => FileOp::Write,
    }
}
