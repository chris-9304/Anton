//! 4-Layer defense: Rate limit (A), Entropy (B), Extensions (C), Network/DNS (D).
//! Plus Owlyshield-like behavioral layer: process families, traversal, coordinated entropy.
//! All engines accept &AnalysisConfig in score methods; if the feature is disabled, return 0.0.

use crate::behavior_engine::{event_type_to_file_op, BehaviorEngine, FileOp};
use crate::crypto::CryptoEngine;
use crate::models::{AnalysisConfig, EventType, FileEvent};
use crate::models::ThreatLevel;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime};

const RATE_WINDOW_SECS: f64 = 0.5;
const RATE_THRESHOLD: usize = 5;
const ENTROPY_HEADER_BYTES: usize = 4096;
const HIGH_ENTROPY_THRESHOLD: f64 = 7.5;

// ---- A. FrequencyAnalyzer (Rate limiting): >5 files modified/renamed in <0.5s (tuned for Rust speed) ----

pub struct FrequencyAnalyzer {
    window: Duration,
    threshold: usize,
    events: VecDeque<(SystemTime, EventType)>,
}

impl FrequencyAnalyzer {
    pub fn new() -> Self {
        Self {
            window: Duration::from_secs_f64(RATE_WINDOW_SECS),
            threshold: RATE_THRESHOLD,
            events: VecDeque::new(),
        }
    }

    pub fn push(&mut self, ev: &FileEvent) {
        let now = ev.timestamp;
        self.events.push_back((now, ev.event_type));
        self.evict(now);
    }

    fn evict(&mut self, now: SystemTime) {
        while let Some((t, _)) = self.events.front() {
            if now.duration_since(*t).unwrap_or_default() > self.window {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    fn count_modify_rename(&self) -> usize {
        self.events
            .iter()
            .filter(|(_, ty)| matches!(ty, EventType::Modified | EventType::Moved))
            .count()
    }

    pub fn rename_burst(&self) -> bool {
        self.events
            .iter()
            .filter(|(_, ty)| *ty == EventType::Moved)
            .count()
            >= self.threshold
    }

    pub fn modify_burst(&self) -> bool {
        self.events
            .iter()
            .filter(|(_, ty)| *ty == EventType::Modified)
            .count()
            >= self.threshold
    }

    pub fn delete_burst(&self) -> bool {
        self.events
            .iter()
            .filter(|(_, ty)| *ty == EventType::Deleted)
            .count()
            >= 3
    }

    /// Returns 0.0 if rate limiting is disabled; otherwise score from modify+rename count in window.
    pub fn frequency_score(&self, config: &AnalysisConfig) -> f32 {
        if !config.enable_rate_limit {
            return 0.0;
        }
        let n = self.count_modify_rename();
        let r = (n as f32) / (self.threshold.max(1) as f32);
        r.clamp(0.0, 1.0)
    }
}

// ---- B. EntropyAnalyzer: first 4096 bytes only; Shannon entropy > 7.5 = encrypted ----

pub struct EntropyAnalyzer {
    window: Duration,
    samples: VecDeque<(SystemTime, f64)>,
}

impl EntropyAnalyzer {
    pub fn new(time_window_secs: f64) -> Self {
        Self {
            window: Duration::from_secs_f64(time_window_secs),
            samples: VecDeque::new(),
        }
    }

    pub fn push(&mut self, ev: &FileEvent) {
        if ev.event_type != EventType::Modified {
            return;
        }
        let mut buf = vec![0u8; ENTROPY_HEADER_BYTES];
        let n = File::open(&ev.src)
            .ok()
            .and_then(|mut f| f.read(&mut buf).ok())
            .unwrap_or(0);
        if n == 0 {
            return;
        }
        let data = &buf[..n];
        let entropy = CryptoEngine::calculate_entropy(data);
        let now = ev.timestamp;
        self.samples.push_back((now, entropy));
        self.evict(now);
    }

    fn evict(&mut self, now: SystemTime) {
        while let Some((t, _)) = self.samples.front() {
            if now.duration_since(*t).unwrap_or_default() > self.window {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    /// Returns 0.0 if entropy check is disabled; otherwise fraction of samples with entropy > 7.5.
    pub fn entropy_score(&self, config: &AnalysisConfig) -> f32 {
        if !config.enable_entropy {
            return 0.0;
        }
        if self.samples.is_empty() {
            return 0.0;
        }
        let high = self
            .samples
            .iter()
            .filter(|(_, e)| *e > HIGH_ENTROPY_THRESHOLD)
            .count();
        (high as f32 / self.samples.len().max(1) as f32).clamp(0.0, 1.0)
    }
}

// ---- C. ExtensionAnalyzer: known bad extensions (incl. .cordyceps, .enc, .locked, .rust, .fun) ----

static BAD_EXTENSIONS: &[&str] = &[
    "locked", "crypt", "encrypted", "encrypt", "vault", "secure",
    "xxx", "zzz", "aaa", "micro", "crypto", "kraken", "teslacrypt",
    "cerber", "locky", "petya", "wannacry", "ryuk", "maze",
    "cordyceps", "enc", "rust", "fun",
];

pub struct ExtensionAnalyzer {
    window: Duration,
    entries: VecDeque<(SystemTime, String)>,
    min_mass: usize,
}

impl ExtensionAnalyzer {
    pub fn new(min_mass: usize, time_window_secs: f64) -> Self {
        Self {
            window: Duration::from_secs_f64(time_window_secs),
            entries: VecDeque::new(),
            min_mass,
        }
    }

    pub fn push(&mut self, ev: &FileEvent) {
        if ev.event_type != EventType::Moved {
            return;
        }
        if let Some(dest) = &ev.dest {
            let ext = dest
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            if !ext.is_empty() {
                let now = ev.timestamp;
                self.entries.push_back((now, ext));
                self.evict(now);
            }
        }
    }

    fn evict(&mut self, now: SystemTime) {
        while let Some((t, _)) = self.entries.front() {
            if now.duration_since(*t).unwrap_or_default() > self.window {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }

    /// Returns 0.0 if extension check is disabled; otherwise score from bad-extension mass.
    pub fn extension_score(&self, config: &AnalysisConfig) -> f32 {
        if !config.enable_extensions {
            return 0.0;
        }
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for (_, ext) in &self.entries {
            *counts.entry(ext.as_str()).or_default() += 1;
        }
        let max = counts.values().copied().max().unwrap_or(0);
        if max < self.min_mass {
            return 0.0;
        }
        let is_known_bad = counts
            .keys()
            .any(|ext| BAD_EXTENSIONS.iter().any(|&b| ext.contains(b)));
        let base = (max as f32 / (self.min_mass as f32 + 5.0)).clamp(0.0, 1.0);
        if is_known_bad {
            base.max(0.9)
        } else {
            base
        }
    }
}

// ---- BehaviorAnalyzer (unchanged; used by AiEngine for automation score) ----

pub struct BehaviorAnalyzer {
    window: Duration,
    times: VecDeque<SystemTime>,
}

impl BehaviorAnalyzer {
    pub fn new(time_window_secs: f64) -> Self {
        Self {
            window: Duration::from_secs_f64(time_window_secs),
            times: VecDeque::new(),
        }
    }

    pub fn push(&mut self, ev: &FileEvent) {
        let now = ev.timestamp;
        self.times.push_back(now);
        self.evict(now);
    }

    fn evict(&mut self, now: SystemTime) {
        while let Some(t) = self.times.front() {
            if now.duration_since(*t).unwrap_or_default() > self.window {
                self.times.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn automation_score(&self) -> f32 {
        if self.times.len() < 3 {
            return 0.0;
        }
        let mut intervals: Vec<f32> = Vec::new();
        let slices = self.times.as_slices();
        for win in slices.0.windows(2) {
            if let [a, b] = win {
                let dt = b.duration_since(*a).unwrap_or_default();
                intervals.push(dt.as_secs_f32());
            }
        }
        if intervals.is_empty() {
            return 0.0;
        }
        let mean = intervals.iter().copied().sum::<f32>() / intervals.len() as f32;
        if mean <= 0.0 {
            return 1.0;
        }
        let var = intervals
            .iter()
            .map(|v| {
                let d = v - mean;
                d * d
            })
            .sum::<f32>()
            / intervals.len() as f32;
        let std = var.sqrt();
        let cv = std / mean;
        let regularity = if cv <= 0.2 { 1.0 - (cv / 0.2) } else { 0.0 };
        let count_factor = (self.times.len() as f32 / 20.0).clamp(0.0, 1.0);
        0.6 * regularity + 0.4 * count_factor
    }
}

// ---- D. NetworkAnalyzer: check_domain against blocklist (tor2web, pastebin, etc.) ----

static DOMAIN_BLOCKLIST: &[&str] = &[
    "tor2web",
    "pastebin",
    "evil.com",
    "c2-server.xyz",
    "malware-c2.local",
    "ransomware-c2.xyz",
];

pub struct NetworkAnalyzer;

impl NetworkAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Returns true if the domain is blocked (malicious). If DNS check is disabled, returns false (allow).
    pub fn check_domain(&self, config: &AnalysisConfig, domain: &str) -> bool {
        if !config.enable_dns {
            return false;
        }
        let d = domain.to_lowercase();
        DOMAIN_BLOCKLIST.iter().any(|&b| d.contains(b))
    }
}

impl Default for NetworkAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---- Behavioral layer (Owlyshield-like): process families + traversal + coordinated entropy ----

/// Push a file event into the behavior engine and get a threat level.
/// When PID is not available from the watcher (e.g. notify doesn't provide it), pass 0 so all events are grouped under one "unknown" root.
/// Returns Critical when traversal_score > 0.8 and entropy_trend > 0.7 (coordinated attack).
pub fn on_file_event(
    behavior_engine: &mut BehaviorEngine,
    pid: u32,
    path: &Path,
    entropy: f32,
    op: FileOp,
) -> ThreatLevel {
    let family_score = behavior_engine.update(pid, path, entropy as f64, op);
    if family_score.traversal_score > 0.8 && family_score.entropy_trend > 0.7 {
        return ThreatLevel::Critical; // Coordinated attack
    }
    if family_score.ramp_up_score > 0.8 && family_score.entropy_trend > 0.5 {
        return ThreatLevel::High;
    }
    ThreatLevel::None
}

/// Convert a FileEvent + optional entropy into FileOp for the behavior engine.
pub fn file_event_to_op(ev: &FileEvent, _entropy: f32) -> FileOp {
    event_type_to_file_op(ev.event_type)
}
