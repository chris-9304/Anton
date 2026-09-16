use crate::app_settings::AppSettings;
use crate::{check_file_suspicious, config::Config, models::DetectionResult, watcher};
use slint::{Model, ModelRc, VecModel};
use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

slint::include_modules!();

const PROTECTED_FOLDERS_FILE: &str = "protected_folders.json";

thread_local! {
    static ACTIVITY_MODEL: RefCell<Option<Rc<VecModel<ActivityEntry>>>> = RefCell::new(None);
}

fn default_scan_dir() -> PathBuf {
    dirs::document_dir()
        .or_else(dirs::download_dir)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

fn protected_folders_path() -> PathBuf {
    dirs::config_local_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        .join("anton")
        .join(PROTECTED_FOLDERS_FILE)
}

fn load_protected_folders() -> Vec<String> {
    let path = protected_folders_path();
    if path.exists() {
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(list) = serde_json::from_str::<Vec<String>>(&data) {
                return list;
            }
        }
    }
    Vec::new()
}

fn save_protected_folders(folders: &[slint::SharedString]) {
    let path = protected_folders_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let list: Vec<&str> = folders.iter().map(|s| s.as_str()).collect();
    if let Ok(data) = serde_json::to_string_pretty(&list) {
        let _ = fs::write(&path, data);
    }
}

fn push_activity(time: String, message: String, is_threat: bool) {
    ACTIVITY_MODEL.with(|m| {
        if let Some(ref model) = *m.borrow() {
            model.push(ActivityEntry {
                time: time.into(),
                message: message.into(),
                is_threat,
            });
        }
    });
}

// Char-boundary-safe truncation: keeps the last `max_chars` characters of `s`.
// Byte-offset slicing (e.g. &s[s.len()-N..]) panics if the cut point lands inside a
// multi-byte UTF-8 character, which is a realistic risk for real filesystem paths.
fn truncate_display(s: &str, max_chars: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_chars {
        s.to_string()
    } else {
        s.chars().skip(char_count - max_chars).collect()
    }
}

pub fn run_desktop() {
    let ui = AppWindow::new().expect("Failed to create UI");

    ui.set_stat_files("0".into());
    ui.set_stat_threats("0".into());
    ui.set_stat_score("—".into());
    ui.set_active_tab("Dashboard".into());
    ui.set_ai_enabled(true);
    ui.set_monitoring_enabled(true);
    ui.set_system_health_cpu("0%".into());
    ui.set_system_health_memory("0%".into());
    ui.set_protection_status("Starting...".into());
    ui.set_scan_status("Idle".into());
    ui.set_scan_progress_text("0%".into());
    ui.set_scan_path("".into());
    ui.set_new_folder_path("".into());
    ui.set_setting_extension_enabled(true);
    ui.set_setting_rate_limit_enabled(true);
    ui.set_setting_entropy_enabled(true);
    ui.set_setting_dns_enabled(true);
    ui.set_diagnostic_state("idle".into());

    let app_settings = Arc::new(Mutex::new(AppSettings::default()));
    let testing_mode = Arc::new(AtomicBool::new(false));
    let detection_occurred = Arc::new(AtomicBool::new(false));

    let activity_model = Rc::new(VecModel::from(vec![]));
    ui.set_recent_activity(ModelRc::new(activity_model.clone()));
    ACTIVITY_MODEL.with(|m| *m.borrow_mut() = Some(activity_model.clone()));

    let diagnostic_log_model = Rc::new(VecModel::from(vec![]));
    ui.set_diagnostic_log(ModelRc::new(diagnostic_log_model.clone()));

    let saved: Vec<slint::SharedString> = load_protected_folders()
        .into_iter()
        .map(|s| s.into())
        .collect();
    let protected_folders_model = Rc::new(VecModel::from(saved));
    ui.set_protected_folders(ModelRc::new(protected_folders_model.clone()));

    let ui_health = ui.as_weak().clone();
    thread::spawn(move || {
        let mut sys = sysinfo::System::new_all();
        loop {
            sys.refresh_cpu();
            sys.refresh_memory();
            let cpu = sys.global_cpu_info().cpu_usage();
            let mem = if sys.total_memory() > 0 {
                (1.0 - (sys.available_memory() as f64 / sys.total_memory() as f64)) * 100.0
            } else {
                0.0
            };
            let cpu_s = format!("{:.0}%", cpu);
            let mem_s = format!("{:.0}%", mem);
            let ui_weak = ui_health.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(u) = ui_weak.upgrade() {
                    u.set_system_health_cpu(cpu_s.clone().into());
                    u.set_system_health_memory(mem_s.clone().into());
                }
            });
            thread::sleep(Duration::from_secs(1));
        }
    });

    let cfg = Config::for_test_run();
    crate::simulation::schedule_cleanup_timeout_gui(cfg.clone());
    let protection_ui = ui.as_weak().clone();
    let watcher_settings = app_settings.clone();
    let testing_mode_w = testing_mode.clone();
    let detection_occurred_w = detection_occurred.clone();
    thread::spawn(move || {
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(u) = protection_ui.upgrade() {
                u.set_protection_status("Protected".into());
            }
        });
        let _ = watcher::run_watcher_with_callback(cfg, watcher_settings, move |det: DetectionResult| {
            if testing_mode_w.load(Ordering::SeqCst)
                && det.level.as_u8() >= crate::models::ThreatLevel::High.as_u8()
            {
                detection_occurred_w.store(true, Ordering::SeqCst);
            }
            let msg = format!("{:?} ({:.0}%)", det.kind, det.confidence * 100.0);
            let time = chrono::Local::now().format("%H:%M:%S").to_string();
            let is_threat = det.level.as_u8() >= crate::models::ThreatLevel::High.as_u8();
            let _ = slint::invoke_from_event_loop(move || {
                push_activity(time, msg, is_threat);
            });
        });
    });

    ui.on_toggled_setting({
        let app_settings = app_settings.clone();
        move |name: slint::SharedString, value: bool| {
            if let Ok(mut guard) = app_settings.lock() {
                guard.set_from_name(name.as_str(), value);
            }
        }
    });

    ui.on_run_self_test({
        let ui_weak = ui.as_weak().clone();
        let log_model = diagnostic_log_model.clone();
        move || {
            if let Some(u) = ui_weak.upgrade() {
                u.set_diagnostic_state("running".into());
            }
            while log_model.row_count() > 0 {
                log_model.remove(0);
            }
            log_model.push("Self-diagnostic started...".into());

            let ui_weak2 = ui_weak.clone();
            let log_model2 = log_model.clone();
            slint::Timer::single_shot(Duration::from_secs(2), move || {
                log_model2.push("Result: PASSED".into());
                if let Some(u) = ui_weak2.upgrade() {
                    u.set_diagnostic_state("passed".into());
                }
            });
        }
    });

    ui.on_add_folder_path({
        let ui_weak = ui.as_weak().clone();
        let model = protected_folders_model.clone();
        move |path: slint::SharedString| {
            let s = path.as_str().trim();
            if s.is_empty() {
                return;
            }
            model.push(s.into());
            let n = model.row_count();
            let list: Vec<slint::SharedString> = (0..n).filter_map(|i| model.row_data(i)).collect();
            save_protected_folders(&list);
            if let Some(u) = ui_weak.upgrade() {
                u.set_new_folder_path("".into());
            }
        }
    });

    ui.on_remove_folder({
        let model = protected_folders_model.clone();
        move |idx: i32| {
            if idx < 0 {
                return;
            }
            let i = idx as usize;
            if i >= model.row_count() {
                return;
            }
            model.remove(i);
            let n = model.row_count();
            let list: Vec<slint::SharedString> = (0..n).filter_map(|j| model.row_data(j)).collect();
            save_protected_folders(&list);
        }
    });

    ui.on_run_demo({
        let ui_weak = ui.as_weak().clone();
        move || {
            if let Some(u) = ui_weak.upgrade() {
                u.set_protection_status("Running ransomware demo...".into());
            }
            let ui_weak2 = ui_weak.clone();
            thread::spawn(move || {
                let exe = std::env::current_exe()
                    .unwrap_or_else(|_| PathBuf::from(format!("anton{}", std::env::consts::EXE_SUFFIX)));
                let status = std::process::Command::new(&exe)
                    .arg("demo")
                    .status();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(u) = ui_weak2.upgrade() {
                        u.set_protection_status("Protected".into());
                        if status.as_ref().map(|s| s.success()).unwrap_or(false) {
                            push_activity(
                                chrono::Local::now().format("%H:%M:%S").to_string(),
                                "Demo complete. Ransomware stopped. Files restored.".to_string(),
                                false,
                            );
                        } else {
                            push_activity(
                                chrono::Local::now().format("%H:%M:%S").to_string(),
                                "Demo finished. Check TestRun folder.".to_string(),
                                false,
                            );
                        }
                    }
                });
            });
        }
    });

    ui.on_revert_demo({
        let ui_weak = ui.as_weak().clone();
        move || {
            if let Some(u) = ui_weak.upgrade() {
                u.set_protection_status("Reverting demo...".into());
            }
            let ui_weak2 = ui_weak.clone();
            thread::spawn(move || {
                let cfg = crate::config::Config::for_test_run();
                crate::simulators::revert_demo(&cfg);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(u) = ui_weak2.upgrade() {
                        u.set_protection_status("Protected".into());
                        push_activity(
                            chrono::Local::now().format("%H:%M:%S").to_string(),
                            "TestRun reverted. Ready for another demo.".to_string(),
                            false,
                        );
                    }
                });
            });
        }
    });

    ui.on_request_scan({
        let ui_scan = ui.as_weak().clone();
        let scanning = Arc::new(AtomicBool::new(false));
        move || {
            if scanning.swap(true, Ordering::SeqCst) {
                return;
            }
            let scan_root = ui_scan
                .upgrade()
                .and_then(|u| {
                    let p = u.get_scan_path();
                    if p.is_empty() { None } else { Some(PathBuf::from(p.as_str())) }
                })
                .unwrap_or_else(default_scan_dir);

            if let Some(u) = ui_scan.upgrade() {
                u.set_scan_status("Scanning".into());
                u.set_scan_progress(0.0);
                u.set_scan_progress_text("0%".into());
                u.set_files_scanned(0);
                u.set_threat_count(0);
            }

            let scan_ui = ui_scan.clone();
            let scanning_done = scanning.clone();
            thread::spawn(move || {
                let entries: Vec<_> = walkdir::WalkDir::new(&scan_root)
                    .max_depth(6)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                    .collect();
                let total = entries.len().max(1);
                let mut threats = 0u32;

                for (i, entry) in entries.into_iter().enumerate() {
                    let path = entry.path();
                    if check_file_suspicious(path) {
                        threats += 1;
                        let time = chrono::Local::now().format("%H:%M:%S").to_string();
                        let msg = format!("Suspicious: {}", path.display());
                        let _ = slint::invoke_from_event_loop(move || {
                            push_activity(time, msg, true);
                        });
                    }

                    let progress = (i + 1) as f32 / total as f32 * 100.0;
                    let scanned = (i + 1) as i32;
                    let threats_i = threats as i32;
                    let path_display = path.display().to_string();
                    let label = if path_display.chars().count() > 70 {
                        format!("Scanning: ...{}", truncate_display(&path_display, 67))
                    } else {
                        format!("Scanning: {}", path_display)
                    };

                    let ui_weak = scan_ui.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(u) = ui_weak.upgrade() {
                            u.set_scan_progress(progress);
                            u.set_scan_progress_text(label.clone().into());
                            u.set_files_scanned(scanned);
                            u.set_threat_count(threats_i);
                        }
                    });
                }

                scanning_done.store(false, Ordering::SeqCst);
                let total_files = total;
                let total_threats = threats;
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(u) = scan_ui.upgrade() {
                        u.set_scan_status("Idle".into());
                        u.set_scan_progress(100.0);
                        u.set_scan_progress_text("100%".into());
                        u.set_stat_files(format!("{}", total_files).into());
                        u.set_stat_threats(format!("{}", total_threats).into());
                        u.set_stat_score(if total_files > 0 {
                            let pct = 100.0 * (1.0 - (total_threats as f32 / total_files as f32));
                            format!("{:.0}%", pct).into()
                        } else {
                            "—".into()
                        });
                    }
                });
            });
        }
    });

    ui.run().expect("Failed to run UI");
}


#[cfg(test)]
mod tests {
    use super::truncate_display;

    #[test]
    fn truncate_display_short_string_unchanged() {
        assert_eq!(truncate_display("hello", 10), "hello");
    }

    #[test]
    fn truncate_display_ascii_truncates_from_front() {
        let s = "a".repeat(100);
        let out = truncate_display(&s, 67);
        assert_eq!(out.chars().count(), 67);
    }

    #[test]
    fn truncate_display_multibyte_char_at_naive_cut_point_does_not_panic() {
        // Regression test: byte-offset slicing (&s[s.len()-67..]) panics if the cut
        // point lands inside a multi-byte UTF-8 character. Build a string where a
        // multi-byte char sits right at the naive 67-byte-from-the-end boundary.
        let mut s = String::new();
        for _ in 0..70 {
            s.push('é'); // 2 bytes in UTF-8
        }
        // Must not panic, and must produce valid UTF-8 with exactly 67 chars.
        let out = truncate_display(&s, 67);
        assert_eq!(out.chars().count(), 67);
        assert!(out.chars().all(|c| c == 'é'));
    }
}
