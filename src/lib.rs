pub mod ai;
pub mod app_settings;
pub mod behavior_engine;
pub mod canary;
pub mod config;
pub mod crypto;
pub mod demo;
pub mod demo_log;
#[cfg(feature = "desktop")]
pub mod desktop;
pub mod detectors;
pub mod models;
pub mod recovery;
pub mod scanner;
pub mod simulation;
pub mod simulators;
pub mod watcher;

use std::io::Read;
use std::path::Path;

const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    "locked",
    "crypt",
    "cordyceps",
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
    "zombie",
];

// Only the first N bytes are read to check entropy -- reading whole files (some scans
// walk into multi-gigabyte media/archive files) just to compute entropy is a serious
// perf/memory hazard, and entropy of the header is already a good enough signal.
const SUSPICIOUS_HEADER_BYTES: usize = 4096;

pub fn check_file_suspicious(path: &Path) -> bool {
    inspect_file_suspicious(path).unwrap_or(false)
}

pub fn inspect_file_suspicious(path: &Path) -> std::io::Result<bool> {
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Expected regular file",
        ));
    }
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if SUSPICIOUS_EXTENSIONS
        .iter()
        .any(|e| extension.eq_ignore_ascii_case(e))
    {
        return Ok(true);
    }
    let mut file = std::fs::File::open(path)?;
    let mut buffer = [0u8; SUSPICIOUS_HEADER_BYTES];
    let count = file.read(&mut buffer)?;
    Ok(count > 0 && crypto::CryptoEngine::calculate_entropy(&buffer[..count]) > 7.5)
}
