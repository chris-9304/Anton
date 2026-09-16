use anton::watcher;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn run_demo() {
    use std::process::{Command, Stdio};
    use std::sync::atomic::Ordering;

    let cfg = anton::config::Config::for_test_run();
    let test_run_path = cfg.test_run_dir.display().to_string();

    // Initialize demo log
    let log_path = anton::demo_log::demo_log_path(&cfg);
    if let Err(e) = anton::demo_log::DemoLogger::init(&log_path) {
        eprintln!("[!] Failed to init demo log: {}", e);
    } else {
        println!("[*] Demo log: {}", log_path.display());
    }

    anton::demo_log::log_phase("PHASE 1: BACKUP");
    println!("[*] Demo: Backing up TestRun...");
    if let Err(e) = anton::simulators::backup_test_run(&cfg) {
        eprintln!("[!] Backup failed: {}", e);
        anton::demo_log::close_and_flush();
        return;
    }
    println!("[*] Backup done. Starting watcher and demo ransomware (sandboxed to TestRun)...");

    anton::demo_log::log_phase("PHASE 2: MONITORING & RANSOMWARE EXECUTION");
    let detection = Arc::new(AtomicBool::new(false));
    let app_settings = Arc::new(Mutex::new(anton::app_settings::AppSettings::default()));
    let detection_c = detection.clone();
    let cfg_w = cfg.clone();
    let _watcher_handle = thread::spawn(move || {
        let _ = watcher::run_watcher_with_callback(cfg_w, app_settings, move |_| {
            detection_c.store(true, Ordering::SeqCst);
        });
    });

    thread::sleep(Duration::from_millis(1500));

    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|q| q.to_path_buf()));
    let demo_bin_name = format!("demo_ransomware{}", std::env::consts::EXE_SUFFIX);
    let demo_bin = exe_dir
        .as_ref()
        .map(|d| d.join(&demo_bin_name))
        .filter(|p| p.exists())
        .or_else(|| {
            let p = manifest.join("target/debug").join(&demo_bin_name);
            if p.exists() { Some(p) } else { None }
        })
        .or_else(|| {
            let p = manifest.join("target/release").join(&demo_bin_name);
            if p.exists() { Some(p) } else { None }
        });

    let log_path_str = anton::demo_log::demo_log_path(&cfg).to_string_lossy().to_string();
    
    // Small delay to ensure log file is ready for writes from ransomware process
    thread::sleep(Duration::from_millis(100));
    
    let mut child = if let Some(ref bin) = demo_bin {
        Command::new(bin)
            .arg(&test_run_path)
            .arg(&log_path_str)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()
    } else {
        eprintln!("[!] demo_ransomware binary not found. Run: cargo build --bin demo_ransomware");
        anton::simulators::revert_demo(&cfg);
        anton::demo_log::close_and_flush();
        return;
    };

    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    while deadline > std::time::Instant::now() {
        if detection.load(Ordering::SeqCst) {
            println!("[*] Threat detected. Stopping ransomware...");
            break;
        }
        if let Some(ref mut c) = child {
            if c.try_wait().map(|s| s.is_some()).unwrap_or(false) {
                break;
            }
        }
        thread::sleep(Duration::from_millis(200));
    }

    if let Some(ref mut c) = child {
        let _ = c.kill();
    }

    anton::demo_log::log_phase("PHASE 3: REMEDIATION & RECOVERY");
    println!("[*] Reverting: removing locked files and restoring...");
    anton::simulators::revert_demo(&cfg);
    println!("[*] Demo complete. Ransomware stopped. Files restored. Ready for another run.");
    
    anton::demo_log::close_and_flush();
    let log_path = anton::demo_log::demo_log_path(&cfg);
    println!("[*] Demo log saved to: {}", log_path.display());
}

fn run_cli(args: &[String]) {
    let cfg = anton::config::Config::for_test_run();
    match args.get(1).map(|s| s.as_str()) {
        Some("run") => {
            println!("[*] Anton monitoring {:?}", cfg.test_run_dir);
            if let Err(e) = watcher::run_watcher(cfg) {
                eprintln!("[!] Watcher error: {}", e);
            }
        }
        Some("demo") => run_demo(),
        Some("simulate") => {
            match args.get(2).map(|s| s.as_str()) {
                Some("old") => anton::simulators::run_old_ransomware_demo(&cfg),
                Some("modern") => anton::simulators::run_modern_ransomware_demo(&cfg),
                Some("wiper") => anton::simulators::run_wiper_malware_demo(&cfg),
                _ => eprintln!("Usage: anton simulate <old|modern|wiper>"),
            }
        }
        Some("reset") => anton::simulators::reset_test_run_files(&cfg),
        Some("revert") => {
            anton::simulators::revert_demo(&cfg);
            println!("[*] Revert done. TestRun restored.");
        }
        _ => {
            println!("Anton - Professional Anti-Ransomware System");
            println!("Usage:");
            println!("  anton              - Launch desktop UI");
            println!("  anton run          - Start monitoring (CLI)");
            println!("  anton demo         - Run sandboxed ransomware demo then restore");
            println!("  anton simulate <type>  - Run simulator (old|modern|wiper)");
            println!("  anton reset        - Reset TestRun files");
            println!("  anton revert       - Restore TestRun from backup / remove locked files");
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let run_gui = args.len() <= 1
        || args.get(1).map(|s| s == "gui" || s == "--gui").unwrap_or(false);
    if run_gui {
        anton::desktop::run_desktop();
    } else {
        run_cli(&args);
    }
}
