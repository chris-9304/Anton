//! Human-readable demo transcript, intentionally separate from diagnostic tracing.
use chrono::Local;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
lazy_static::lazy_static! { static ref DEMO_LOG: Mutex<Option<DemoLogger>> = Mutex::new(None); }

pub struct DemoLogger {
    path: PathBuf,
}

impl DemoLogger {
    pub fn init(path: &Path) -> std::io::Result<()> {
        // Preserve the previous transcript before starting a new demo.
        if path.exists() {
            fs::rename(path, path.with_extension("txt.1"))?;
        }
        let mut guard = DEMO_LOG.lock().unwrap_or_else(|e| e.into_inner());
        append_log_file(
            path,
            &format!(
                "ANTON — RANSOMWARE DEFENSE DEMO LOG\nTimestamp: {}\n",
                Local::now().format("%Y-%m-%d %H:%M:%S")
            ),
        )?;
        *guard = Some(Self { path: path.into() });
        Ok(())
    }
}

/// Reopen for each append so the demo child observes transcript rotation too.
pub fn append_log_file(path: &Path, message: &str) -> std::io::Result<()> {
    // A single unusually long filesystem path cannot make the transcript unbounded.
    let mut end = message.len().min(64 * 1024);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let message = &message[..end];
    if fs::metadata(path).is_ok_and(|m| m.len() + message.len() as u64 > MAX_LOG_BYTES) {
        match fs::rename(path, path.with_extension("txt.1")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(message.as_bytes())?;
    file.flush()
}

fn write(message: String) {
    if let Some(logger) = &*DEMO_LOG.lock().unwrap_or_else(|e| e.into_inner()) {
        if let Err(error) = append_log_file(&logger.path, &message) {
            tracing::error!(%error, "Demo transcript write failed");
        }
    }
    println!("{}", message.trim());
}

pub fn log_ransomware_action(action: &str, path: &str) {
    write(format!(
        "[RANSOMWARE] {} | {action} | {path}\n",
        Local::now().format("%H:%M:%S%.3f")
    ));
}
pub fn log_detection(kind: &str, level: &str, confidence: f32, path: Option<&str>) {
    write(format!(
        "[ANTON DETECTED] {} | Kind: {kind} | Level: {level} | Confidence: {:.0}% | File: {}\n",
        Local::now().format("%H:%M:%S%.3f"),
        confidence * 100.0,
        path.unwrap_or("(system)")
    ));
}
pub fn log_remediation(action: &str, details: &str) {
    write(format!(
        "[ANTON REMEDIATION] {} | {action} | {details}\n",
        Local::now().format("%H:%M:%S%.3f")
    ));
}
pub fn log_phase(phase: &str) {
    write(format!("\n--- {phase} ---\n"));
}
pub fn demo_log_path(config: &crate::config::Config) -> PathBuf {
    config
        .test_run_dir
        .parent()
        .unwrap_or(&config.test_run_dir)
        .join("demo_log.txt")
}
pub fn close_and_flush() {
    let mut guard = DEMO_LOG.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(logger) = guard.take() {
        if let Err(error) = append_log_file(&logger.path, "\nDemo transcript closed.\n") {
            tracing::error!(%error, "Demo transcript write failed");
        }
    }
}
