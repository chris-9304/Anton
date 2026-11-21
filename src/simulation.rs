//! Safe self-diagnostic sandbox: create a test dir, run red-team simulators, cleanup.
//! All operations are confined to `test_run_dir/anton_sandbox_test/`.

use crate::canary::CanaryManager;
use crate::config::Config;
use rand::Rng;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub const SANDBOX_DIR: &str = "anton_sandbox_test";
const CORD_HEADER: &[u8] = b"CORD";
const CLEANUP_TIMEOUT_SECS: u64 = 30 * 60; // 30 minutes

/// Sandbox root: always under config.test_run_dir so the watcher sees it.
pub fn sandbox_path(config: &Config) -> PathBuf {
    config.test_run_dir.join(SANDBOX_DIR)
}

/// Create sandbox dir and 100 dummy files (text, fake images, fake PDFs). Deploy canaries.
pub fn setup_sandbox(config: &Config) -> std::io::Result<()> {
    let root = sandbox_path(config);
    if config.test_run_dir.is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Sandbox parent cannot be a symbolic link",
        ));
    }
    fs::create_dir_all(&config.test_run_dir)?;
    // Ownership starts here; never reuse or truncate somebody else's sandbox.
    fs::create_dir(&root)?;

    // ~50 .txt, ~25 .jpg (dummy), ~25 .pdf (dummy)
    for i in 0..50 {
        let p = root.join(format!("doc_{}.txt", i));
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)?;
        writeln!(f, "Sample document {} - safe content for testing.", i)?;
    }
    for i in 0..25 {
        let p = root.join(format!("image_{}.jpg", i));
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)?;
        f.write_all(b"\xff\xd8\xff fake jpeg header\n")?;
    }
    for i in 0..25 {
        let p = root.join(format!("report_{}.pdf", i));
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)?;
        f.write_all(b"%PDF-1.4 fake pdf\n")?;
    }

    let canary = CanaryManager;
    canary.deploy(&root);
    Ok(())
}

/// Remove sandbox directory and all contents.
pub fn cleanup_sandbox(config: &Config) {
    let root = sandbox_path(config);
    if root.exists() {
        let _ = fs::remove_dir_all(&root);
    }
}

/// Cordyceps mimic: recursively walk sandbox, rename to .cordyceps, write CORD header.
/// Exits when stop_flag is set.
pub fn run_cordyceps_mimic(config: &Config, stop_flag: Arc<AtomicBool>) {
    let root = sandbox_path(config);
    let entries: Vec<_> = match fs::read_dir(&root) {
        Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
        _ => return,
    };
    for p in entries {
        if stop_flag.load(Ordering::SeqCst) {
            break;
        }
        if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_file()) {
            let mut new_path = p.clone();
            new_path.set_extension("cordyceps");
            if fs::rename(&p, &new_path).is_ok() {
                let _ = File::options()
                    .write(true)
                    .open(&new_path)
                    .and_then(|mut f| f.write_all(CORD_HEADER));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

/// 2) Fast Rust mimic: 5 threads overwriting files with high-entropy data.
pub fn run_fast_rust_mimic(config: &Config, stop_flag: Arc<AtomicBool>) {
    let root = sandbox_path(config);
    let files: Vec<PathBuf> = match fs::read_dir(&root) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file()))
            .collect(),
        _ => return,
    };
    let chunk_size = (files.len() / 5).max(1);
    let mut handles = vec![];
    for chunk in files.chunks(chunk_size) {
        let paths: Vec<PathBuf> = chunk.to_vec();
        let stop = stop_flag.clone();
        handles.push(thread::spawn(move || {
            let mut rng = rand::thread_rng();
            for p in paths {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(mut f) = File::create(&p) {
                    let buf: Vec<u8> = (0..4096).map(|_| rng.gen()).collect();
                    let _ = f.write_all(&buf);
                }
                thread::sleep(Duration::from_millis(5));
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}

/// Canary file names we touch for traverser mimic (subset of canary list).
const HONEYTOKEN_NAMES: &[&str] = &[".sys_config.dat", "_backup_2024.docx", "_passwords.docx"];

/// 3) Traverser mimic: rapidly touch honeytoken files.
pub fn run_traverser_mimic(config: &Config, stop_flag: Arc<AtomicBool>) {
    let root = sandbox_path(config);
    for name in HONEYTOKEN_NAMES {
        if stop_flag.load(Ordering::SeqCst) {
            break;
        }
        let p = root.join(name);
        if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_file()) {
            let _ = File::options()
                .write(true)
                .open(&p)
                .and_then(|mut f| f.write_all(b"touched"));
        }
        thread::sleep(Duration::from_millis(10));
    }
    // Touch multiple times to trigger rate + canary
    for _ in 0..5 {
        if stop_flag.load(Ordering::SeqCst) {
            break;
        }
        for name in HONEYTOKEN_NAMES {
            let p = root.join(name);
            if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_file()) {
                let _ = std::fs::write(&p, b"x");
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Result of the self-test.
#[derive(Clone, Debug)]
pub enum SelfTestResult {
    Pass { message: String },
    Fail { reason: String },
}

/// Run the full self-test: setup sandbox, run all three simulators (in parallel),
/// monitor detection_occurred. If detection triggers -> Pass; else Fail.
/// Sends log lines to log_tx. Sets testing_mode true at start, false at end.
pub fn run_self_test(
    config: Config,
    log_tx: std::sync::mpsc::Sender<String>,
    detection_occurred: Arc<AtomicBool>,
    testing_mode: Arc<AtomicBool>,
) -> SelfTestResult {
    run_self_test_cancellable(
        config,
        log_tx,
        detection_occurred,
        testing_mode,
        Arc::new(AtomicBool::new(false)),
    )
}

pub fn run_self_test_cancellable(
    config: Config,
    log_tx: std::sync::mpsc::Sender<String>,
    detection_occurred: Arc<AtomicBool>,
    testing_mode: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
) -> SelfTestResult {
    run_self_test_with_settings(
        config,
        crate::app_settings::AppSettings::default(),
        log_tx,
        detection_occurred,
        testing_mode,
        cancel,
    )
}

pub fn run_self_test_with_settings(
    config: Config,
    settings: crate::app_settings::AppSettings,
    log_tx: std::sync::mpsc::Sender<String>,
    detection_occurred: Arc<AtomicBool>,
    testing_mode: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
) -> SelfTestResult {
    let send = |s: &str| {
        let _ = log_tx.send(s.to_string());
    };

    detection_occurred.store(false, Ordering::SeqCst);
    testing_mode.store(false, Ordering::SeqCst);
    if !settings.monitoring_enabled {
        send("Result: FAILED — Enable monitoring before running the self-test.");
        return SelfTestResult::Fail {
            reason: "Monitoring is paused".into(),
        };
    }
    testing_mode.store(true, Ordering::SeqCst);

    send("Creating Sandbox...");
    if let Err(e) = setup_sandbox(&config) {
        testing_mode.store(false, Ordering::SeqCst);
        return SelfTestResult::Fail {
            reason: format!("Sandbox setup failed: {}", e),
        };
    }
    send("Sandbox ready. 100 dummy files + honeytokens created.");

    // Subscribe after setup so the test cannot pass by detecting its own canary deployment.
    let watcher_config = Config {
        test_run_dir: sandbox_path(&config),
        ..config.clone()
    };
    let callback_detection = detection_occurred.clone();
    let mut watcher = match crate::watcher::start_watcher(
        watcher_config,
        Arc::new(std::sync::Mutex::new(settings)),
        move |detection| {
            if detection.level >= crate::models::ThreatLevel::High {
                callback_detection.store(true, Ordering::Release);
            }
        },
    ) {
        Ok(watcher) => watcher,
        Err(error) => {
            cleanup_sandbox(&config);
            testing_mode.store(false, Ordering::Release);
            return SelfTestResult::Fail {
                reason: format!("Diagnostic watcher failed: {error}"),
            };
        }
    };
    let stop_flag = Arc::new(AtomicBool::new(false));
    let start = Instant::now();
    let timeout = Duration::from_secs(25);

    send("Simulating Cordyceps Attack...");
    let stop_c = stop_flag.clone();
    let cfg_c = config.clone();
    let t_cord = thread::spawn(move || run_cordyceps_mimic(&cfg_c, stop_c));

    send("Simulating Fast Rust (5 threads, high-entropy overwrite)...");
    let stop_f = stop_flag.clone();
    let cfg_f = config.clone();
    let t_fast = thread::spawn(move || run_fast_rust_mimic(&cfg_f, stop_f));

    send("Simulating Traverser (touching honeytokens)...");
    let stop_t = stop_flag.clone();
    let cfg_t = config.clone();
    let t_trav = thread::spawn(move || run_traverser_mimic(&cfg_t, stop_t));

    let mut detected = false;
    while start.elapsed() < timeout && !cancel.load(Ordering::Acquire) {
        if detection_occurred.load(Ordering::SeqCst) {
            detected = true;
            let elapsed = start.elapsed().as_secs_f32();
            send(&format!("Attack detected in {:.1}s.", elapsed));
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    stop_flag.store(true, Ordering::SeqCst);
    let _ = t_cord.join();
    let _ = t_fast.join();
    let _ = t_trav.join();

    watcher.stop();
    send("Cleaning up...");
    cleanup_sandbox(&config);
    testing_mode.store(false, Ordering::SeqCst);

    if detected {
        send("Result: PASSED — Sandbox attack detected.");
        SelfTestResult::Pass {
            message: "Sandbox attack detected".into(),
        }
    } else {
        send("Result: FAILED — No detection triggered.");
        SelfTestResult::Fail {
            reason: "Detectors did not trigger (Entropy/Extension/Canary/Rate limit check may be disabled or threshold not met).".into(),
        }
    }
}

/// Spawn a background thread that runs cleanup_sandbox after 30 minutes if not already cleaned.
/// For non-GUI callers only (no Slint event loop available to schedule a timer on).
pub fn schedule_cleanup_timeout(config: Config) {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(CLEANUP_TIMEOUT_SECS));
        cleanup_sandbox(&config);
    });
}

/// Same as `schedule_cleanup_timeout`, but for GUI callers: uses a Slint timer instead of
/// parking a dedicated OS thread for the full 30 minutes.
#[cfg(feature = "desktop")]
pub fn schedule_cleanup_timeout_gui(config: Config) {
    slint::Timer::single_shot(Duration::from_secs(CLEANUP_TIMEOUT_SECS), move || {
        cleanup_sandbox(&config);
    });
}
