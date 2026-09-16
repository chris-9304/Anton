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

use std::io::Read;
use std::path::Path;

const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    "locked", "crypt", "cordyceps", "encrypted", "encrypt", "vault", "secure",
    "xxx", "zzz", "aaa", "micro", "crypto", "kraken", "teslacrypt",
    "cerber", "locky", "petya", "wannacry", "ryuk", "maze", "zombie",
];

// Only the first N bytes are read to check entropy -- reading whole files (some scans
// walk into multi-gigabyte media/archive files) just to compute entropy is a serious
// perf/memory hazard, and entropy of the header is already a good enough signal.
const SUSPICIOUS_HEADER_BYTES: usize = 4096;

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
    if let Ok(mut f) = std::fs::File::open(path) {
        let mut buf = vec![0u8; SUSPICIOUS_HEADER_BYTES];
        if let Ok(n) = f.read(&mut buf) {
            if n > 0 && crypto::CryptoEngine::calculate_entropy(&buf[..n]) > 7.5 {
                return true;
            }
        }
    }
    false
}
