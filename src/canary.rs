//! Layer 1: Honeytoken / canary trap for high-speed ransomware.
//! Rust ransomware blindly traverses folders; we place hidden bait files that users never touch.
//! If a canary is modified or deleted -> immediate critical threat.

use std::fs;
use std::io::Write;
use std::path::Path;

/// Names of bait files we deploy. Ransomware that touches these triggers an immediate alert.
const CANARY_FILES: &[&str] = &[
    ".sys_config.dat",
    "_backup_2024.docx",
    "_passwords.docx",
    ".env.backup",
    "thumbs.db.bak",
    ".gitkeep.dat",
];

/// Manages honeytoken (canary) files. Deploy in the watched root; if any are modified or deleted, treat as critical threat.
#[derive(Debug, Default)]
pub struct CanaryManager;

impl CanaryManager {
    /// Create hidden canary (bait) files under `root`. Creates them if they don't exist.
    pub fn deploy(&self, root: &Path) {
        for name in CANARY_FILES {
            let path = root.join(name);
            if path.exists() {
                continue;
            }
            let _ = fs::File::create(&path).and_then(|mut f| f.write_all(b"canary"));
        }
    }

    /// Returns true if the given path is one of our known canary (bait) files.
    pub fn is_canary(&self, path: &Path) -> bool {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        CANARY_FILES.contains(&name)
    }
}
