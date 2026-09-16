use crate::ai::AiEngine;
use crate::app_settings::AppSettings;
use crate::canary::CanaryManager;
use crate::config::Config;
use crate::models::{
    AnalysisConfig, DetectionResult, DetectionSignals, EventType, FileEvent, ThreatKind,
    ThreatLevel,
};
use crate::simulators::cleanup_and_reset_after_ransomware;
use chrono;
use notify::event::ModifyKind;
use notify::{
    recommended_watcher, Event, EventKind, RecursiveMode, Result as NotifyResult, Watcher,
};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

fn to_event(e: &Event) -> Option<FileEvent> {
    let ts = SystemTime::now();
    let kind = match &e.kind {
        EventKind::Create(_) => EventType::Created,
        EventKind::Modify(ModifyKind::Name(_)) => EventType::Moved,
        EventKind::Modify(_) => EventType::Modified,
        EventKind::Remove(_) => EventType::Deleted,
        _ => return None,
    };
    let src = e.paths.get(0)?.clone();
    let dest = if matches!(&e.kind, EventKind::Modify(ModifyKind::Name(_))) {
        e.paths.get(1).cloned()
    } else {
        None
    };
    Some(FileEvent {
        event_type: kind,
        src,
        dest,
        timestamp: ts,
    })
}

pub fn run_watcher_with_callback<F>(
    config: Config,
    settings: Arc<Mutex<AppSettings>>,
    on_det: F,
) -> NotifyResult<()>
where
    F: Fn(DetectionResult) + Send + Sync + 'static,
{
    std::fs::create_dir_all(&config.test_run_dir)?;

    let canary_manager = CanaryManager::default();
    canary_manager.deploy(&config.test_run_dir);

    let shared_cfg = Arc::new(config.clone());
    let engine = Arc::new(Mutex::new(AiEngine::new(&shared_cfg)));

    let cfg_clone = shared_cfg.clone();
    let engine_clone = engine.clone();
    let settings_clone = settings.clone();
    let cb = Arc::new(on_det);

    let mut watcher = recommended_watcher(move |res: NotifyResult<Event>| {
        if let Ok(ev) = res {
            if let Some(file_ev) = to_event(&ev) {
                let det_result = {
                    let path = &file_ev.src;
                    let is_canary_touched = canary_manager.is_canary(path)
                        && matches!(file_ev.event_type, EventType::Modified | EventType::Deleted);

                    if is_canary_touched {
                        DetectionResult {
                            kind: ThreatKind::HoneytokenTouched,
                            level: ThreatLevel::Critical,
                            confidence: 1.0,
                            signals: DetectionSignals {
                                frequency_score: 0.0,
                                extension_score: 0.0,
                                behavior_score: 0.0,
                                entropy_score: 0.0,
                            },
                            timestamp: chrono::Local::now().to_rfc3339(),
                            file_path: path.to_str().map(|s| s.to_string()),
                        }
                    } else {
                        let mut guard = engine_clone.lock().unwrap();
                        guard.on_event(&file_ev);
                        let app_settings = settings_clone.lock().unwrap();
                        let analysis_config = AnalysisConfig {
                            enable_extensions: app_settings.extension_monitoring,
                            enable_entropy: app_settings.entropy,
                            enable_rate_limit: app_settings.rate_limit,
                            enable_dns: app_settings.dns,
                        };
                        let mut det = guard.evaluate(&analysis_config);
                        det.file_path = file_ev.src.to_str().map(|s| s.to_string());
                        det
                    }
                };

                cb(det_result.clone());

                // Log detection to demo log
                crate::demo_log::log_detection(
                    &format!("{:?}", det_result.kind),
                    &format!("{:?}", det_result.level),
                    det_result.confidence,
                    det_result.file_path.as_deref(),
                );

                if det_result.level.as_u8() >= ThreatLevel::High.as_u8() {
                    if matches!(
                        det_result.kind,
                        ThreatKind::RansomwareModern
                            | ThreatKind::RansomwareOld
                            | ThreatKind::RansomwareTraverser
                            | ThreatKind::HighEntropyStorm
                            | ThreatKind::HoneytokenTouched
                    ) {
                        crate::demo_log::log_remediation("RANSOMWARE_BLOCKED", "Initiating cleanup and file restoration");
                        cleanup_and_reset_after_ransomware(&cfg_clone);
                    } else if matches!(det_result.kind, ThreatKind::WiperMalware) {
                        crate::demo_log::log_remediation("WIPER_MALWARE_BLOCKED", "Resetting protected files");
                        crate::simulators::reset_test_run_files(&cfg_clone);
                    }
                }
            }
        }
    })?;

    watcher.watch(&shared_cfg.test_run_dir, RecursiveMode::Recursive)?;

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

pub fn run_watcher(config: Config) -> NotifyResult<()> {
    let settings = Arc::new(Mutex::new(AppSettings::default()));
    run_watcher_with_callback(config, settings, |det| {
        println!(
            "[watch] {:?} level={:?} conf={:.0}% freq={:.2} ext={:.2} beh={:.2}",
            det.kind,
            det.level,
            det.confidence * 100.0,
            det.signals.frequency_score,
            det.signals.extension_score,
            det.signals.behavior_score,
        );
    })
}


