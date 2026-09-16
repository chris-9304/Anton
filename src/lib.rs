pub mod app_settings;
pub mod behavior_engine;
pub mod canary;
pub mod config;
pub mod models;
pub mod ai;
pub mod detectors;
pub mod watcher;
pub mod simulators;
pub mod simulation;
pub mod recovery;
pub mod crypto;
pub mod desktop;
pub mod demo_log;

use std::path::Path;

const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    "locked", "crypt", "cordyceps", "encrypted", "encrypt", "vault", "secure",
    "xxx", "zzz", "aaa", "micro", "crypto", "kraken", "teslacrypt",
    "cerber", "locky", "petya", "wannacry", "ryuk", "maze", "zombie",
];

pub fn check_file_suspicious(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    if SUSPICIOUS_EXTENSIONS
        .iter()
        .any(|&e| ext.as_str() == e)
    {
        return true;
    }
    if let Ok(data) = std::fs::read(path) {
        if !data.is_empty() && crypto::CryptoEngine::calculate_entropy(&data) > 7.5 {
            return true;
        }
    }
    false
}
