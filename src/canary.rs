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
        if let Err(error) = self.try_deploy(root) {
            tracing::error!(%error, "Canary deployment failed");
        }
    }

    pub fn try_deploy(&self, root: &Path) -> std::io::Result<()> {
        for name in CANARY_FILES {
            let path = root.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_file() => continue,
                Ok(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Canary path is not a regular file",
                    ))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?
                .write_all(b"canary")?;
        }
        Ok(())
    }

    /// Returns true if the given path is one of our known canary (bait) files.
    pub fn is_canary(&self, path: &Path) -> bool {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        CANARY_FILES.contains(&name)
    }
}
