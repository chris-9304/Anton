use crate::{
    app_settings::AppSettings,
    config::Config,
    models::{DetectionResult, ThreatLevel},
    scanner::{scan_tree, ScanProgress},
    watcher,
};
use slint::{Model, ModelRc, VecModel};
use std::{
    cell::RefCell,
    collections::VecDeque,
    fs,
    path::PathBuf,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
slint::include_modules!();
const PROTECTED_FOLDERS_FILE: &str = "protected_folders.json";
thread_local! { static ACTIVITY_MODEL: RefCell<Option<Rc<VecModel<ActivityEntry>>>> = const { RefCell::new(None) }; }
type ActivityQueue = Arc<Mutex<VecDeque<(String, String, bool)>>>;
fn enqueue(queue: &ActivityQueue, message: String, threat: bool) {
    let mut queue = queue.lock().unwrap_or_else(|e| e.into_inner());
    if queue.len() >= 1000 {
        queue.pop_front();
    }
    queue.push_back((
        chrono::Local::now().format("%H:%M:%S").to_string(),
        message,
        threat,
    ));
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

fn save_protected_folders(
    folders: &[slint::SharedString],
) -> Result<(), Box<dyn std::error::Error>> {
    let path = protected_folders_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let list: Vec<&str> = folders.iter().map(|s| s.as_str()).collect();
    let data = serde_json::to_vec_pretty(&list)?;
    let temporary = path.with_file_name(format!(".anton-folders-{}", rand::random::<u64>()));
    let result = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result?;
    Ok(())
}

fn push_activity(time: String, message: String, is_threat: bool) {
    ACTIVITY_MODEL.with(|m| {
        if let Some(ref model) = *m.borrow() {
            if model.row_count() >= 1000 {
                model.remove(0);
            }
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
    let settings = Arc::new(Mutex::new(AppSettings::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let busy = Arc::new(AtomicBool::new(false));
    let testing = Arc::new(AtomicBool::new(false));
    let detected = Arc::new(AtomicBool::new(false));
    let activity: ActivityQueue = Arc::new(Mutex::new(VecDeque::new()));
    let scan = Arc::new(Mutex::new(None::<ScanProgress>));
    let diagnostic = Arc::new(Mutex::new(None::<(Vec<String>, bool)>));
    let workers = Rc::new(RefCell::new(Vec::<thread::JoinHandle<()>>::new()));
    let model = Rc::new(VecModel::from(Vec::<ActivityEntry>::new()));
    ACTIVITY_MODEL.with(|m| *m.borrow_mut() = Some(model.clone()));
    ui.set_recent_activity(ModelRc::new(model));
    let diagnostic_model = Rc::new(VecModel::from(Vec::<slint::SharedString>::new()));
    ui.set_diagnostic_log(ModelRc::new(diagnostic_model.clone()));
    let folders = Rc::new(VecModel::from(
        load_protected_folders()
            .into_iter()
            .map(Into::into)
            .collect::<Vec<slint::SharedString>>(),
    ));
    ui.set_protected_folders(ModelRc::new(folders.clone()));

    let queue = activity.clone();
    let test_flag = testing.clone();
    let detection_flag = detected.clone();
    let mut watcher = match watcher::start_watcher(
        Config::for_test_run(),
        settings.clone(),
        move |det: DetectionResult| {
            if det.level >= ThreatLevel::High && test_flag.load(Ordering::Acquire) {
                detection_flag.store(true, Ordering::Release);
            }
            if det.level != ThreatLevel::None {
                enqueue(
                    &queue,
                    format!("{:?} ({:.0}%)", det.kind, det.confidence * 100.0),
                    det.level >= ThreatLevel::High,
                );
            }
        },
    ) {
        Ok(handle) => Some(handle),
        Err(error) => {
            enqueue(&activity, format!("Monitoring failed: {error}"), true);
            None
        }
    };
    let health = watcher.as_ref().map(|w| w.health.clone());
    let timer = slint::Timer::default();
    let ui_tick = ui.as_weak();
    let tick_activity = activity.clone();
    let tick_scan = scan.clone();
    let tick_diagnostic = diagnostic.clone();
    let tick_busy = busy.clone();
    let tick_settings = settings.clone();
    let tick_workers = workers.clone();
    let mut system = sysinfo::System::new();
    let mut health_time = Instant::now() - Duration::from_secs(1);
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(100),
        move || {
            let Some(ui) = ui_tick.upgrade() else {
                return;
            };
            ui.set_operation_busy(tick_busy.load(Ordering::Acquire));
            {
                let mut queue = tick_activity.lock().unwrap_or_else(|e| e.into_inner());
                for _ in 0..100 {
                    let Some((time, message, threat)) = queue.pop_front() else {
                        break;
                    };
                    push_activity(time, message, threat);
                }
            }
            if let Some(progress) = tick_scan.lock().unwrap_or_else(|e| e.into_inner()).take() {
                ui.set_files_scanned(progress.files.min(i32::MAX as u64) as i32);
                ui.set_threat_count(progress.threats.min(i32::MAX as u64) as i32);
                if progress.complete {
                    ui.set_scan_status(
                        if progress.error.is_some() {
                            "Failed"
                        } else {
                            "Complete"
                        }
                        .into(),
                    );
                    ui.set_scan_progress(100.0);
                    ui.set_scan_progress_text(
                        progress
                            .error
                            .unwrap_or_else(|| {
                                format!(
                                    "{} files scanned · {} suspicious · {} skipped",
                                    progress.files, progress.threats, progress.skipped
                                )
                            })
                            .into(),
                    );
                    ui.set_stat_files(progress.files.to_string().into());
                    ui.set_stat_threats(progress.threats.to_string().into());
                    ui.set_stat_score(if progress.files == 0 {
                        "—".into()
                    } else {
                        format!(
                            "{:.0}%",
                            100.0 * (1.0 - progress.threats as f64 / progress.files as f64)
                        )
                        .into()
                    });
                } else {
                    ui.set_scan_progress_text(
                        format!(
                            "{} files · {} skipped · {}",
                            progress.files,
                            progress.skipped,
                            truncate_display(&progress.path, 67)
                        )
                        .into(),
                    );
                }
            }
            if let Some((lines, passed)) = tick_diagnostic
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                diagnostic_model.set_vec(lines.into_iter().map(Into::into).collect::<Vec<_>>());
                ui.set_diagnostic_state(if passed { "passed" } else { "failed" }.into());
            }
            if health_time.elapsed() >= Duration::from_secs(1) {
                system.refresh_cpu();
                system.refresh_memory();
                ui.set_system_health_cpu(
                    format!("{:.0}%", system.global_cpu_info().cpu_usage()).into(),
                );
                let memory = if system.total_memory() == 0 {
                    0.0
                } else {
                    100.0 * (1.0 - system.available_memory() as f64 / system.total_memory() as f64)
                };
                ui.set_system_health_memory(format!("{memory:.0}%").into());
                health_time = Instant::now();
            }
            let current = tick_settings
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            ui.set_ai_enabled(current.ai_enabled);
            ui.set_monitoring_enabled(current.monitoring_enabled);
            let status = match &health {
                None => "Monitoring unavailable",
                Some(h) if h.degraded.load(Ordering::Acquire) => {
                    "Monitoring degraded — restart required"
                }
                Some(h) if !h.ready.load(Ordering::Acquire) => "Monitoring stopped",
                _ if tick_busy.load(Ordering::Acquire) => "Operation in progress",
                _ if !current.monitoring_enabled => "Monitoring paused",
                _ if !current.ai_enabled => "Canary protection only",
                _ => "Monitoring TestRun",
            };
            ui.set_protection_status(status.into());
            tick_workers
                .borrow_mut()
                .retain(|worker| !worker.is_finished());
        },
    );

    ui.on_toggled_setting({
        let settings = settings.clone();
        move |name, value| {
            settings
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .set_from_name(name.as_str(), value);
        }
    });
    ui.on_add_folder_path({
        let folders = folders.clone();
        let ui = ui.as_weak();
        let activity = activity.clone();
        move |path: slint::SharedString| {
            let path = path.trim();
            if path.is_empty() || folders.iter().any(|p| p.as_str() == path) {
                return;
            }
            let mut next: Vec<_> = folders.iter().collect();
            next.push(path.into());
            match save_protected_folders(&next) {
                Ok(()) => {
                    folders.push(path.into());
                    if let Some(ui) = ui.upgrade() {
                        ui.set_new_folder_path("".into());
                    }
                }
                Err(error) => enqueue(&activity, format!("Could not save folders: {error}"), false),
            }
        }
    });
    ui.on_remove_folder({
        let folders = folders.clone();
        let activity = activity.clone();
        move |index| {
            if index < 0 || index as usize >= folders.row_count() {
                return;
            }
            let next: Vec<_> = folders
                .iter()
                .enumerate()
                .filter_map(|(i, path)| (i != index as usize).then_some(path))
                .collect();
            match save_protected_folders(&next) {
                Ok(()) => {
                    folders.remove(index as usize);
                }
                Err(error) => enqueue(&activity, format!("Could not save folders: {error}"), false),
            }
        }
    });

    ui.on_request_scan({
        let ui = ui.as_weak();
        let busy = busy.clone();
        let stop = stop.clone();
        let scan = scan.clone();
        let activity = activity.clone();
        let workers = workers.clone();
        move || {
            if busy.swap(true, Ordering::AcqRel) {
                return;
            }
            let root = ui
                .upgrade()
                .map(|u| u.get_scan_path())
                .filter(|p| !p.trim().is_empty())
                .map(|p| PathBuf::from(p.trim()))
                .unwrap_or_else(default_scan_dir);
            if let Some(ui) = ui.upgrade() {
                ui.set_operation_busy(true);
                ui.set_scan_status("Scanning".into());
                ui.set_files_scanned(0);
                ui.set_threat_count(0);
                ui.set_scan_progress(0.0);
                ui.set_scan_progress_text("Scanning…".into());
            }
            let scan = scan.clone();
            let busy = busy.clone();
            let stop = stop.clone();
            let activity = activity.clone();
            workers.borrow_mut().push(thread::spawn(move || {
                let result = scan_tree(&root, &stop, |value| {
                    *scan.lock().unwrap_or_else(|e| e.into_inner()) = Some(value)
                });
                enqueue(
                    &activity,
                    format!(
                        "Scan ended: {} files, {} suspicious, {} skipped{}",
                        result.files,
                        result.threats,
                        result.skipped,
                        result.error.map(|e| format!(" — {e}")).unwrap_or_default()
                    ),
                    result.threats > 0,
                );
                busy.store(false, Ordering::Release);
            }));
        }
    });

    ui.on_run_self_test({
        let settings = settings.clone();
        let ui = ui.as_weak();
        let busy = busy.clone();
        let testing = testing.clone();
        let detected = detected.clone();
        let diagnostic = diagnostic.clone();
        let workers = workers.clone();
        let stop = stop.clone();
        move || {
            if busy.swap(true, Ordering::AcqRel) {
                return;
            }
            if let Some(ui) = ui.upgrade() {
                ui.set_diagnostic_state("running".into());
                ui.set_operation_busy(true);
            }
            let settings = settings.clone();
            let busy = busy.clone();
            let testing = testing.clone();
            let detected = detected.clone();
            let diagnostic = diagnostic.clone();
            let stop = stop.clone();
            workers.borrow_mut().push(thread::spawn(move || {
                let snapshot = {
                    let mut current = settings.lock().unwrap_or_else(|e| e.into_inner());
                    let snapshot = current.clone();
                    current.set_from_name("monitoring", false);
                    snapshot
                };
                let was_monitoring = snapshot.monitoring_enabled;
                let (tx, rx) = std::sync::mpsc::channel();
                let result = crate::simulation::run_self_test_with_settings(
                    Config::for_test_run(),
                    snapshot,
                    tx,
                    detected,
                    testing,
                    stop.clone(),
                );
                for _ in 0..20 {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                settings
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .set_from_name("monitoring", was_monitoring);
                let passed = matches!(result, crate::simulation::SelfTestResult::Pass { .. });
                *diagnostic.lock().unwrap_or_else(|e| e.into_inner()) = Some((
                    {
                        let mut lines: Vec<_> = rx.try_iter().take(100).collect();
                        if let crate::simulation::SelfTestResult::Fail { reason } = result {
                            lines.push(reason);
                        }
                        lines
                    },
                    passed,
                ));
                busy.store(false, Ordering::Release);
            }));
        }
    });

    // Both actions temporarily pause this subscription to avoid competing remediation
    // with the independent CLI demo watcher and delayed restore notifications.
    for (is_demo, register) in [(true, 0), (false, 1)] {
        let ui_weak = ui.as_weak();
        let busy = busy.clone();
        let settings = settings.clone();
        let activity = activity.clone();
        let workers = workers.clone();
        let stop = stop.clone();
        let action = move || {
            if busy.swap(true, Ordering::AcqRel) {
                return;
            }
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_operation_busy(true);
            }
            let busy = busy.clone();
            let settings = settings.clone();
            let activity = activity.clone();
            let stop = stop.clone();
            workers.borrow_mut().push(thread::spawn(move || {
                let was_monitoring = {
                    let mut current = settings.lock().unwrap_or_else(|e| e.into_inner());
                    let previous = current.monitoring_enabled;
                    current.set_from_name("monitoring", false);
                    previous
                };
                let result = if is_demo {
                    crate::demo::run_demo(Config::for_test_run(), stop.clone())
                        .map_err(|error| format!("{error:#}"))
                } else {
                    crate::simulators::try_revert_demo(&Config::for_test_run())
                        .map_err(|e| e.to_string())
                };
                // Keep late FSEvents generated by restoration out of analysis.
                for _ in 0..20 {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                settings
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .set_from_name("monitoring", was_monitoring);
                enqueue(
                    &activity,
                    match &result {
                        Ok(()) => "Demo files restored.".into(),
                        Err(error) => format!("Operation failed: {error}"),
                    },
                    result.is_err(),
                );
                busy.store(false, Ordering::Release);
            }));
        };
        if register == 0 {
            ui.on_run_demo(action);
        } else {
            ui.on_revert_demo(action);
        }
    }
    ui.run().expect("Failed to run UI");
    timer.stop();
    stop.store(true, Ordering::Release);
    if let Some(watcher) = watcher.as_mut() {
        watcher.stop();
    }
    for worker in workers.borrow_mut().drain(..) {
        let _ = worker.join();
    }
    ACTIVITY_MODEL.with(|model| *model.borrow_mut() = None);
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
