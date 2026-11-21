//! 4-Layer defense: Rate limit (A), Entropy (B), Extensions (C), Network/DNS (D).
//! Plus Owlyshield-like behavioral layer: process families, traversal, coordinated entropy.
//! All engines accept &AnalysisConfig in score methods; if the feature is disabled, return 0.0.

use crate::behavior_engine::{event_type_to_file_op, BehaviorEngine, FileOp};
use crate::crypto::CryptoEngine;
use crate::models::ThreatLevel;
use crate::models::{AnalysisConfig, EventType, FileEvent};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime};

const SAMPLE_CAP: usize = 4096;

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

impl Default for FrequencyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
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
        if self.events.len() == SAMPLE_CAP {
            self.events.pop_front();
        }
        self.events.push_back((now, ev.event_type));
        self.evict(now);
    }

    pub(crate) fn evict(&mut self, now: SystemTime) {
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

    /// `header`: the file's already-read leading bytes, if the caller has them (avoids
    /// a second open+read of the same file the caller likely just read itself). Falls
    /// back to reading the file here if `None`.
    pub fn push(&mut self, ev: &FileEvent, header: Option<&[u8]>) {
        self.evict(ev.timestamp);
        if ev.event_type != EventType::Modified {
            return;
        }
        let owned_buf;
        let data: &[u8] = match header {
            Some(h) => h,
            None => {
                let mut buf = vec![0u8; ENTROPY_HEADER_BYTES];
                let n = File::open(&ev.src)
                    .ok()
                    .and_then(|mut f| f.read(&mut buf).ok())
                    .unwrap_or(0);
                if n == 0 {
                    return;
                }
                buf.truncate(n);
                owned_buf = buf;
                &owned_buf
            }
        };
        if data.is_empty() {
            return;
        }
        let entropy = CryptoEngine::calculate_entropy(data);
        self.push_sample(ev.timestamp, entropy);
    }

    pub fn push_sample(&mut self, now: SystemTime, entropy: f64) {
        if self.samples.len() == SAMPLE_CAP {
            self.samples.pop_front();
        }
        self.samples.push_back((now, entropy));
        self.evict(now);
    }

    pub(crate) fn evict(&mut self, now: SystemTime) {
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
    "locked",
    "crypt",
    "encrypted",
    "encrypt",
    "vault",
    "secure",
    "xxx",
    "zzz",
    "aaa",
    "micro",
    "crypto",
    "kraken",
    "teslacrypt",
    "cerber",
    "locky",
    "petya",
    "wannacry",
    "ryuk",
    "maze",
    "cordyceps",
    "enc",
    "rust",
    "fun",
];

pub struct ExtensionAnalyzer {
    window: Duration,
    entries: VecDeque<(SystemTime, String)>,
    min_mass: usize,
    counts: HashMap<String, usize>,
}

impl ExtensionAnalyzer {
    pub fn new(min_mass: usize, time_window_secs: f64) -> Self {
        Self {
            window: Duration::from_secs_f64(time_window_secs),
            entries: VecDeque::new(),
            min_mass,
            counts: HashMap::new(),
        }
    }

    pub fn push(&mut self, ev: &FileEvent) {
        self.evict(ev.timestamp);
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
                if self.entries.len() == SAMPLE_CAP {
                    self.pop_front();
                }
                *self.counts.entry(ext.clone()).or_default() += 1;
                self.entries.push_back((now, ext));
                self.evict(now);
            }
        }
    }

    fn pop_front(&mut self) {
        if let Some((_, extension)) = self.entries.pop_front() {
            if let Some(count) = self.counts.get_mut(&extension) {
                *count -= 1;
                if *count == 0 {
                    self.counts.remove(&extension);
                }
            }
        }
    }

    pub(crate) fn evict(&mut self, now: SystemTime) {
        while let Some((t, _)) = self.entries.front() {
            if now.duration_since(*t).unwrap_or_default() > self.window {
                self.pop_front();
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
        let max = self.counts.values().copied().max().unwrap_or(0);
        if max < self.min_mass {
            return 0.0;
        }
        let is_known_bad = self
            .counts
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
        if self.times.len() == SAMPLE_CAP {
            self.times.pop_front();
        }
        self.times.push_back(now);
        self.evict(now);
    }

    pub(crate) fn evict(&mut self, now: SystemTime) {
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
        // Welford's algorithm includes the boundary between both VecDeque slices.
        let mut count = 0usize;
        let mut mean = 0.0f32;
        let mut sum_squares = 0.0f32;
        for (a, b) in self.times.iter().zip(self.times.iter().skip(1)) {
            let interval = b.duration_since(*a).unwrap_or_default().as_secs_f32();
            count += 1;
            let delta = interval - mean;
            mean += delta / count as f32;
            sum_squares += delta * (interval - mean);
        }
        if mean <= 0.0 {
            return 1.0;
        }
        let std = (sum_squares / count as f32).max(0.0).sqrt();
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

#[cfg(test)]
mod tests {
    use super::*;
    fn event(time: SystemTime, kind: EventType) -> FileEvent {
        FileEvent {
            timestamp: time,
            event_type: kind,
            src: "report.txt".into(),
            dest: Some("report.locked".into()),
        }
    }

    #[test]
    fn wrapped_behavior_buffer_matches_contiguous_buffer() {
        let mut wrapped = BehaviorAnalyzer::new(10.0);
        let now = SystemTime::now();
        for i in 0..100 {
            wrapped.times.push_back(now + Duration::from_millis(i));
        }
        for _ in 0..90 {
            wrapped.times.pop_front();
        }
        for i in 100..180 {
            wrapped.times.push_back(now + Duration::from_millis(i));
        }
        let mut contiguous = BehaviorAnalyzer::new(10.0);
        contiguous.times = wrapped.times.iter().copied().collect();
        assert!((wrapped.automation_score() - contiguous.automation_score()).abs() < 0.00001);
    }

    #[test]
    fn windows_expire_and_bursts_remain_detectable_at_capacity() {
        let now = SystemTime::now();
        let mut frequency = FrequencyAnalyzer::new();
        let mut extensions = ExtensionAnalyzer::new(5, 10.0);
        let mut entropy = EntropyAnalyzer::new(10.0);
        let mut behavior = BehaviorAnalyzer::new(10.0);
        for _ in 0..10_000 {
            let event = event(now, EventType::Moved);
            frequency.push(&event);
            extensions.push(&event);
            entropy.push_sample(now, 8.0);
            behavior.push(&event);
        }
        assert_eq!(frequency.events.len(), SAMPLE_CAP);
        assert_eq!(extensions.entries.len(), SAMPLE_CAP);
        assert_eq!(entropy.samples.len(), SAMPLE_CAP);
        assert_eq!(behavior.times.len(), SAMPLE_CAP);
        let config = AnalysisConfig::default();
        assert!(frequency.rename_burst());
        assert!(extensions.extension_score(&config) >= 0.9);
        assert_eq!(entropy.entropy_score(&config), 1.0);
        let later = now + Duration::from_secs(11);
        frequency.evict(later);
        extensions.evict(later);
        entropy.evict(later);
        behavior.evict(later);
        assert_eq!(frequency.frequency_score(&config), 0.0);
        assert_eq!(extensions.extension_score(&config), 0.0);
        assert!(extensions.counts.is_empty());
        assert_eq!(entropy.entropy_score(&config), 0.0);
        assert_eq!(behavior.automation_score(), 0.0);
    }
}
