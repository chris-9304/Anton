use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use chrono::Local;

lazy_static::lazy_static! {
    static ref DEMO_LOG: Arc<Mutex<Option<DemoLogger>>> = Arc::new(Mutex::new(None));
}

pub struct DemoLogger {
    file: File,
}

impl DemoLogger {
    pub fn init(log_path: &Path) -> std::io::Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(log_path)?;
        
        let mut logger = DemoLogger { file };
        logger.write_header()?;
        
        let mut guard = DEMO_LOG.lock().unwrap();
        *guard = Some(logger);
        Ok(())
    }

    fn write_header(&mut self) -> std::io::Result<()> {
        writeln!(
            self.file,
            "================================================================================\n\
             ANTON - RANSOMWARE DEFENSE DEMO LOG\n\
             ================================================================================\n\
             Timestamp: {}\n\
             ================================================================================\n",
            Local::now().format("%Y-%m-%d %H:%M:%S")
        )?;
        self.file.flush()?;
        Ok(())
    }

    fn write_raw(&mut self, msg: &str) -> std::io::Result<()> {
        write!(self.file, "{}", msg)?;
        self.file.flush()?;
        Ok(())
    }
}

/// Log directly to a shared file (for use in separate processes like demo_ransomware)
/// This does NOT hold the file lock - it opens, writes, and closes.
pub fn append_log_file(log_path: &Path, msg: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        
        .create(true)
        .append(true)
        .open(log_path)?;
    write!(file, "{}", msg)?;
    file.flush()?;
    drop(file); // Explicitly close before returning
    Ok(())
}

/// Log a ransomware action (encryption, file rename, etc.)
pub fn log_ransomware_action(action: &str, file_path: &str) {
    let msg = format!(
        "[RANSOMWARE] {} | {} | {}\n",
        Local::now().format("%H:%M:%S%.3f"),
        action,
        file_path
    );
    if let Ok(mut guard) = DEMO_LOG.lock() {
        if let Some(ref mut logger) = *guard {
            let _ = logger.write_raw(&msg);
        }
    }
    println!("{}", msg.trim());
}

/// Log an Anton detection
pub fn log_detection(kind: &str, level: &str, confidence: f32, file_path: Option<&str>) {
    let path_str = file_path.unwrap_or("(system)");
    let msg = format!(
        "[ANTON DETECTED] {} | Kind: {} | Level: {} | Confidence: {:.0}% | File: {}\n",
        Local::now().format("%H:%M:%S%.3f"),
        kind,
        level,
        confidence * 100.0,
        path_str
    );
    if let Ok(mut guard) = DEMO_LOG.lock() {
        if let Some(ref mut logger) = *guard {
            let _ = logger.write_raw(&msg);
        }
    }
    println!("{}", msg.trim());
}

/// Log a remediation/cleanup action by Anton
pub fn log_remediation(action: &str, details: &str) {
    let msg = format!(
        "[ANTON REMEDIATION] {} | {} | {}\n",
        Local::now().format("%H:%M:%S%.3f"),
        action,
        details
    );
    if let Ok(mut guard) = DEMO_LOG.lock() {
        if let Some(ref mut logger) = *guard {
            let _ = logger.write_raw(&msg);
        }
    }
    println!("{}", msg.trim());
}

/// Log demo phase transitions
pub fn log_phase(phase: &str) {
    let msg = format!(
        "\n--- {} ---\n",
        phase
    );
    if let Ok(mut guard) = DEMO_LOG.lock() {
        if let Some(ref mut logger) = *guard {
            let _ = logger.write_raw(&msg);
        }
    }
    println!("{}", msg.trim());
}

/// Get the demo log file path
pub fn demo_log_path(config: &crate::config::Config) -> PathBuf {
    config.test_run_dir.parent()
        .unwrap_or(&config.test_run_dir)
        .join("demo_log.txt")
}

pub fn close_and_flush() {
    if let Ok(mut guard) = DEMO_LOG.lock() {
        if let Some(ref mut logger) = *guard {
            let _ = writeln!(logger.file, "\n================================================================================");
            let _ = writeln!(logger.file, "Demo complete. Log ends here.");
            let _ = writeln!(logger.file, "================================================================================");
            let _ = logger.file.flush();
        }
        *guard = None;
    }
}
