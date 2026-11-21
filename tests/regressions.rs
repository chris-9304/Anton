use anton::{
    app_settings::AppSettings, config::Config, crypto::CryptoEngine, recovery::RecoveryEngine,
    scanner::scan_tree, simulators, watcher::start_watcher,
};
use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    time::{Duration, Instant},
};

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("anton-test-{}", rand::random::<u64>()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn config(&self) -> Config {
        Config::for_production(&self.0)
    }
    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn shadow_copies_are_unique_verified_and_restore_original_bytes() {
    let sandbox = Sandbox::new();
    let recovery = RecoveryEngine::new(&sandbox.config());
    let first = sandbox.file("first/report.txt", b"first report");
    let second = sandbox.file("second/report.txt", b"second report");
    let a = recovery.create_shadow_copy(&first).unwrap();
    let b = recovery.create_shadow_copy(&second).unwrap();
    assert_ne!(a, b);
    fs::write(&first, b"corrupted").unwrap();
    recovery.restore_from_shadow(&a, &first).unwrap();
    assert_eq!(fs::read(&first).unwrap(), b"first report");
    fs::write(&a, b"tampered").unwrap();
    assert!(recovery.restore_from_shadow(&a, &first).is_err());
    assert_eq!(fs::read(&first).unwrap(), b"first report");
}

#[test]
fn encrypted_artifacts_are_retained_without_a_verified_original() {
    let sandbox = Sandbox::new();
    let recovery = RecoveryEngine::new(&sandbox.config());
    let original = sandbox.file("reports/report.txt", b"original");
    recovery.create_shadow_copy(&original).unwrap();
    let encrypted = original.with_file_name("report.txt.LOCKED");
    fs::rename(&original, &encrypted).unwrap();
    fs::write(&encrypted, b"encrypted").unwrap();
    let unknown = sandbox.file("reports/unknown.txt.locked", b"unknown");
    assert_eq!(
        recovery
            .cleanup_encrypted_files(&sandbox.0.join("reports"))
            .unwrap(),
        1
    );
    assert!(!encrypted.exists());
    assert!(unknown.exists());
    assert_eq!(fs::read(original).unwrap(), b"original");
}

#[test]
fn backup_restores_nested_files_and_preserves_previous_backup() {
    let sandbox = Sandbox::new();
    let cfg = sandbox.config();
    fs::create_dir_all(&cfg.test_run_dir).unwrap();
    let original = cfg.test_run_dir.join("nested/report.txt");
    fs::create_dir_all(original.parent().unwrap()).unwrap();
    fs::write(&original, b"nested content").unwrap();
    simulators::backup_test_run(&cfg).unwrap();
    assert!(simulators::backup_test_run(&cfg).is_err());
    fs::write(&original, b"damaged").unwrap();
    fs::write(cfg.test_run_dir.join("new.locked"), b"artifact").unwrap();
    simulators::try_revert_demo(&cfg).unwrap();
    assert_eq!(fs::read(original).unwrap(), b"nested content");
    assert!(!cfg.test_run_dir.join("new.locked").exists());
    assert!(!sandbox.0.join("TestRun_backup").exists());
}

#[cfg(unix)]
#[test]
fn backup_and_scanner_do_not_follow_symbolic_links() {
    use std::os::unix::fs::symlink;
    let sandbox = Sandbox::new();
    let cfg = sandbox.config();
    let outside = sandbox.file("outside.txt", b"never modify");
    fs::create_dir_all(&cfg.test_run_dir).unwrap();
    symlink(&outside, cfg.test_run_dir.join("link.txt")).unwrap();
    assert!(simulators::backup_test_run(&cfg).is_err());
    let result = scan_tree(&cfg.test_run_dir, &AtomicBool::new(false), |_| {});
    assert_eq!(result.files, 0);
    assert_eq!(fs::read(outside).unwrap(), b"never modify");
}

#[cfg(unix)]
#[test]
fn self_test_refuses_a_symbolic_link_sandbox() {
    use std::os::unix::fs::symlink;
    let sandbox = Sandbox::new();
    let config = sandbox.config();
    fs::create_dir_all(&config.test_run_dir).unwrap();
    let outside = sandbox.0.join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, anton::simulation::sandbox_path(&config)).unwrap();
    assert!(anton::simulation::setup_sandbox(&config).is_err());
    assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
}

#[test]
fn empty_missing_cancelled_and_large_file_scans_are_honest() {
    let sandbox = Sandbox::new();
    let result = scan_tree(&sandbox.0, &AtomicBool::new(false), |_| {});
    assert_eq!(result.files, 0);
    assert!(result.error.is_none());
    assert!(
        scan_tree(&sandbox.0.join("missing"), &AtomicBool::new(false), |_| {})
            .error
            .is_some()
    );
    let large = sandbox.file("large.txt", b"small header");
    fs::OpenOptions::new()
        .write(true)
        .open(&large)
        .unwrap()
        .set_len(256 * 1024 * 1024)
        .unwrap();
    let result = scan_tree(&sandbox.0, &AtomicBool::new(false), |_| {});
    assert_eq!(result.files, 1);
    assert_eq!(result.threats, 0);
    assert!(scan_tree(&sandbox.0, &AtomicBool::new(true), |_| {})
        .error
        .is_some());
}

#[test]
fn invalid_crypto_keys_return_errors_instead_of_panicking() {
    for key in [&[][..], &[0u8; 31][..], &[0u8; 33][..]] {
        assert!(CryptoEngine::encrypt_aes256gcm(b"data", key).is_err());
        assert!(CryptoEngine::decrypt_aes256gcm(&[0u8; 64], key).is_err());
        assert!(CryptoEngine::encrypt_chacha20poly1305(b"data", key).is_err());
        assert!(CryptoEngine::decrypt_chacha20poly1305(&[0u8; 64], key).is_err());
    }
    let key = [42u8; 32];
    let encrypted = CryptoEngine::encrypt_chacha20poly1305(b"data", &key).unwrap();
    assert_eq!(
        CryptoEngine::decrypt_chacha20poly1305(&encrypted, &key).unwrap(),
        b"data"
    );
}

#[test]
fn watcher_obeys_monitoring_pause_retains_canaries_without_ai_and_stops() {
    let sandbox = Sandbox::new();
    let config = sandbox.config();
    let settings = Arc::new(Mutex::new(AppSettings {
        monitoring_enabled: false,
        ai_enabled: false,
        ..AppSettings::default()
    }));
    let (tx, rx) = mpsc::channel();
    let mut watcher = start_watcher(config.clone(), settings.clone(), move |d| {
        let _ = tx.send(d);
    })
    .unwrap();
    let canary = config.test_run_dir.join(".sys_config.dat");
    fs::write(&canary, b"changed while paused").unwrap();
    assert!(rx.recv_timeout(Duration::from_secs(2)).is_err());
    settings.lock().unwrap().set_from_name("monitoring", true);
    fs::write(canary, b"changed after resume").unwrap();
    let detection = rx
        .recv_timeout(Duration::from_secs(6))
        .expect("canary detection");
    assert_eq!(detection.kind, anton::models::ThreatKind::HoneytokenTouched);
    assert!(
        rx.recv_timeout(Duration::from_secs(3)).is_err(),
        "recovery must not detect itself"
    );
    let start = Instant::now();
    watcher.stop();
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(!watcher.health.ready.load(Ordering::Acquire));
}

#[test]
#[ignore = "resource workload; run explicitly with --ignored --nocapture"]
fn scan_ten_thousand_files() {
    let sandbox = Sandbox::new();
    for i in 0..10_000 {
        sandbox.file(
            &format!("folder-{}/file-{i}.txt", i % 100),
            b"plain sample document",
        );
    }
    let mut publications = 0;
    let start = Instant::now();
    let result = scan_tree(&sandbox.0, &AtomicBool::new(false), |_| publications += 1);
    assert_eq!(result.files, 10_000);
    assert_eq!(result.skipped, 0);
    assert!(publications <= (start.elapsed().as_millis() / 100) + 2);
    println!(
        "scan: files={} elapsed_ms={} progress_publications={publications}",
        result.files,
        start.elapsed().as_millis()
    );
}

#[test]
fn diagnostic_owns_its_watcher_and_preserves_parent_files() {
    let sandbox = Sandbox::new();
    let config = sandbox.config();
    fs::create_dir_all(&config.test_run_dir).unwrap();
    let original = config.test_run_dir.join("valuable.txt");
    fs::write(&original, b"preserve parent file").unwrap();
    let (tx, _rx) = mpsc::channel();
    let detected = Arc::new(AtomicBool::new(false));
    let testing = Arc::new(AtomicBool::new(false));
    let result = anton::simulation::run_self_test_with_settings(
        config.clone(),
        AppSettings::default(),
        tx,
        detected.clone(),
        testing.clone(),
        Arc::new(AtomicBool::new(false)),
    );
    assert!(
        matches!(result, anton::simulation::SelfTestResult::Pass { .. }),
        "{result:?}"
    );
    assert!(detected.load(Ordering::Acquire));
    assert!(!testing.load(Ordering::Acquire));
    assert!(!anton::simulation::sandbox_path(&config).exists());
    assert_eq!(fs::read(original).unwrap(), b"preserve parent file");
}

#[test]
fn disabled_monitoring_cannot_report_a_successful_diagnostic() {
    let sandbox = Sandbox::new();
    let config = sandbox.config();
    let (tx, _rx) = mpsc::channel();
    let detected = Arc::new(AtomicBool::new(false));
    let testing = Arc::new(AtomicBool::new(false));
    let result = anton::simulation::run_self_test_with_settings(
        config.clone(),
        AppSettings {
            monitoring_enabled: false,
            ..AppSettings::default()
        },
        tx,
        detected.clone(),
        testing.clone(),
        Arc::new(AtomicBool::new(false)),
    );
    assert!(matches!(
        result,
        anton::simulation::SelfTestResult::Fail { .. }
    ));
    assert!(!detected.load(Ordering::Acquire));
    assert!(!testing.load(Ordering::Acquire));
    assert!(!anton::simulation::sandbox_path(&config).exists());
}
