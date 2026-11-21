//! Streaming, bounded-memory scanning shared independently of the UI.
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default)]
pub struct ScanProgress {
    pub files: u64,
    pub threats: u64,
    pub skipped: u64,
    pub path: String,
    pub complete: bool,
    pub error: Option<String>,
}

pub fn scan_tree(
    root: &Path,
    stop: &AtomicBool,
    mut publish: impl FnMut(ScanProgress),
) -> ScanProgress {
    let mut progress = ScanProgress::default();
    if !root.is_dir() || root.is_symlink() {
        progress.error = Some("Choose an existing folder that is not a symbolic link".into());
        progress.complete = true;
        publish(progress.clone());
        return progress;
    }
    let mut last_update = Instant::now();
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .max_depth(6)
        .max_open(16)
    {
        if stop.load(Ordering::Acquire) {
            progress.error = Some("Scan cancelled".into());
            break;
        }
        match entry {
            Ok(entry) if entry.file_type().is_file() => {
                match crate::inspect_file_suspicious(entry.path()) {
                    Ok(suspicious) => {
                        progress.files += 1;
                        progress.threats += suspicious as u64;
                    }
                    Err(_) => progress.skipped += 1,
                }
                if last_update.elapsed() >= Duration::from_millis(100) {
                    progress.path = entry.path().display().to_string();
                    publish(progress.clone());
                    last_update = Instant::now();
                }
            }
            Err(_) => progress.skipped += 1,
            _ => {}
        }
    }
    progress.complete = true;
    publish(progress.clone());
    progress
}
