use serde::Serialize;
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EventType {
    Created,
    Modified,
    Deleted,
    Moved,
}

#[derive(Debug, Clone)]
pub struct FileEvent {
    pub event_type: EventType,
    pub src: PathBuf,
    pub dest: Option<PathBuf>,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ThreatKind {
    Benign,
    RansomwareOld,
    RansomwareModern,
    WiperMalware,
    /// High-speed Rust-style ransomware that traverses directories quickly.
    RansomwareTraverser,
    /// A honeytoken/canary file was modified or deleted (immediate critical).
    HoneytokenTouched,
    /// Many files raised to high entropy in a short time (encryption storm).
    HighEntropyStorm,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ThreatLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatLevel {
    pub fn as_u8(self) -> u8 {
        match self {
            ThreatLevel::None => 0,
            ThreatLevel::Low => 1,
            ThreatLevel::Medium => 2,
            ThreatLevel::High => 3,
            ThreatLevel::Critical => 4,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionSignals {
    pub frequency_score: f32,
    pub extension_score: f32,
    pub behavior_score: f32,
    pub entropy_score: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionResult {
    pub kind: ThreatKind,
    pub level: ThreatLevel,
    pub confidence: f32,
    pub signals: DetectionSignals,
    pub timestamp: String,
    pub file_path: Option<String>,
}

/// Runtime analysis toggles from Settings UI. Passed to analyzers so they can skip work when disabled.
#[derive(Debug, Clone, Copy)]
pub struct AnalysisConfig {
    pub enable_extensions: bool,
    pub enable_entropy: bool,
    pub enable_rate_limit: bool,
    pub enable_dns: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            enable_extensions: true,
            enable_entropy: true,
            enable_rate_limit: true,
            enable_dns: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanRecord {
    pub id: u64,
    #[serde(rename = "type")]
    pub scan_type: String,
    pub result: String,
    pub timestamp: String,
    pub threats_found: u32,
}
