//! One demo controller for CLI and desktop, with owned watcher and child lifetimes.
use crate::{app_settings::AppSettings, config::Config, models::ThreatLevel, simulators, watcher};
use anyhow::{bail, Context, Result};
use std::{
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

struct DemoChild(Child);
impl Drop for DemoChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Transcript;
impl Drop for Transcript {
    fn drop(&mut self) {
        crate::demo_log::close_and_flush();
    }
}

pub fn run_demo(config: Config, cancel: Arc<AtomicBool>) -> Result<()> {
    let executable = std::env::current_exe()?;
    let binary = executable
        .parent()
        .context("Missing executable directory")?
        .join(format!("demo_ransomware{}", std::env::consts::EXE_SUFFIX));
    run_demo_with_binary(config, cancel, &binary)
}

fn run_demo_with_binary(
    config: Config,
    cancel: Arc<AtomicBool>,
    binary: &std::path::Path,
) -> Result<()> {
    if !binary.is_file() {
        bail!("Missing sibling demo_ransomware executable; build or install both binaries");
    }
    simulators::backup_test_run(&config).context("Backup failed; no demo was started")?;
    crate::demo_log::DemoLogger::init(&crate::demo_log::demo_log_path(&config))?;
    let _transcript = Transcript;
    crate::demo_log::log_phase("BACKUP COMPLETE — STARTING MONITORING");
    let detected = Arc::new(AtomicBool::new(false));
    let detection = detected.clone();
    let mut watcher = watcher::start_watcher(
        config.clone(),
        Arc::new(Mutex::new(AppSettings::default())),
        move |result| {
            if result.level >= ThreatLevel::High {
                detection.store(true, Ordering::Release);
            }
        },
    )?;
    let spawned = Command::new(binary)
        .arg(&config.test_run_dir)
        .arg(crate::demo_log::demo_log_path(&config))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match spawned {
        Ok(child) => DemoChild(child),
        Err(error) => {
            watcher.stop();
            return Err(error).context("Demo could not start; backup retained");
        }
    };
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut cancelled = false;
    loop {
        if cancel.load(Ordering::Acquire) {
            cancelled = true;
            break;
        }
        if detected.load(Ordering::Acquire) {
            break;
        }
        if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    drop(child); // Kill and reap before restoring any files.
    watcher.stop();
    crate::demo_log::log_phase("RESTORING BACKUP");
    simulators::try_revert_demo(&config).context("Restore failed; backup retained")?;
    if cancelled {
        crate::demo_log::log_phase("DEMO CANCELLED — FILES RESTORED");
        bail!("Demo cancelled; files restored");
    }
    if !detected.load(Ordering::Acquire) {
        crate::demo_log::log_phase("NO HIGH-SEVERITY DETECTION — FILES RESTORED");
        bail!("Demo finished without a high-severity detection; files restored");
    }
    crate::demo_log::log_phase("THREAT DETECTED — FILES RESTORED");
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn repeated_demo_cycles_stop_children_and_restore_nested_files() {
        let root = std::env::temp_dir().join(format!("anton-demo-test-{}", rand::random::<u64>()));
        fs::create_dir_all(&root).unwrap();
        let result = (|| -> Result<()> {
            let config = Config::for_production(&root);
            fs::create_dir_all(config.test_run_dir.join("nested"))?;
            let original = config.test_run_dir.join("nested/original.txt");
            fs::write(&original, b"preserve this document")?;
            let simulator = root.join("simulator");
            fs::write(
                &simulator,
                "#!/bin/sh\nprintf changed > \"$1/.sys_config.dat\"\nexec sleep 10\n",
            )?;
            fs::set_permissions(&simulator, fs::Permissions::from_mode(0o700))?;
            for _ in 0..3 {
                run_demo_with_binary(config.clone(), Arc::new(AtomicBool::new(false)), &simulator)?;
                assert_eq!(fs::read(&original)?, b"preserve this document");
                assert!(!root.join("TestRun_backup").exists());
            }
            let result =
                run_demo_with_binary(config.clone(), Arc::new(AtomicBool::new(true)), &simulator);
            assert!(result.unwrap_err().to_string().contains("cancelled"));
            assert_eq!(fs::read(original)?, b"preserve this document");
            Ok(())
        })();
        let _ = fs::remove_dir_all(root);
        result.unwrap();
    }
}
