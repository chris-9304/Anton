use anton::watcher;
use std::sync::{atomic::AtomicBool, Arc};

fn run_demo() {
    if let Err(error) = anton::demo::run_demo(
        anton::config::Config::for_test_run(),
        Arc::new(AtomicBool::new(false)),
    ) {
        tracing::error!("{error:#}");
        std::process::exit(1);
    }
}

fn run_cli(args: &[String]) {
    let cfg = anton::config::Config::for_test_run();
    match args.get(1).map(|s| s.as_str()) {
        Some("run") => {
            println!("[*] Anton monitoring {:?}", cfg.test_run_dir);
            if let Err(e) = watcher::run_watcher(cfg) {
                tracing::error!("Watcher error: {}", e);
            }
        }
        Some("demo") => run_demo(),
        Some("simulate") => {
            let result = match args.get(2).map(|s| s.as_str()) {
                Some("old") => anton::simulators::run_old_ransomware_demo(&cfg),
                Some("modern") => anton::simulators::run_modern_ransomware_demo(&cfg),
                Some("wiper") => anton::simulators::run_wiper_malware_demo(&cfg),
                _ => {
                    eprintln!("Usage: anton simulate <old|modern|wiper>");
                    return;
                }
            };
            if let Err(e) = result {
                tracing::error!("Simulation error: {}", e);
            }
        }
        Some("reset") => {
            if let Err(e) = anton::simulators::reset_test_run_files(&cfg) {
                tracing::error!("Reset error: {}", e);
            }
        }
        Some("revert") => {
            if let Err(error) = anton::simulators::try_revert_demo(&cfg) {
                tracing::error!(%error, "Restore failed; backup retained");
                std::process::exit(1);
            }
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
    tracing_subscriber::fmt::init();
    let args: Vec<String> = std::env::args().collect();
    let run_gui = args.len() <= 1
        || args
            .get(1)
            .map(|s| s == "gui" || s == "--gui")
            .unwrap_or(false);
    if run_gui {
        #[cfg(feature = "desktop")]
        anton::desktop::run_desktop();
        #[cfg(not(feature = "desktop"))]
        eprintln!("Desktop support is disabled. Use anton run, demo, reset, or revert.");
    } else {
        run_cli(&args);
    }
}
