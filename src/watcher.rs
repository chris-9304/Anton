use crate::ai::AiEngine;
use crate::app_settings::AppSettings;
use crate::canary::CanaryManager;
use crate::config::Config;
use crate::models::{
    AnalysisConfig, DetectionResult, DetectionSignals, EventType, FileEvent, ThreatKind,
    ThreatLevel,
};
use notify::event::ModifyKind;
use notify::{
    recommended_watcher, Event, EventKind, RecursiveMode, Result as NotifyResult, Watcher,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

const REMEDIATION_QUIET_PERIOD: Duration = Duration::from_secs(2);
const EVENT_CAPACITY: usize = 2048;

#[derive(Default)]
pub struct WatcherHealth {
    pub ready: AtomicBool,
    pub degraded: AtomicBool,
    pub dropped_events: AtomicU64,
}

/// Owns the native subscription and its analysis worker. Dropping joins the worker.
pub struct WatcherHandle {
    watcher: Option<notify::RecommendedWatcher>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    pub health: Arc<WatcherHealth>,
}

impl WatcherHandle {
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.watcher.take();
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                self.health.degraded.store(true, Ordering::Release);
            }
        }
        self.health.ready.store(false, Ordering::Release);
    }
}

impl Drop for WatcherHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

fn to_events(e: Event, timestamp: SystemTime) -> Vec<FileEvent> {
    let event_type = match e.kind {
        EventKind::Create(_) => EventType::Created,
        EventKind::Modify(ModifyKind::Name(_)) => EventType::Moved,
        EventKind::Modify(_) => EventType::Modified,
        EventKind::Remove(_) => EventType::Deleted,
        _ => return Vec::new(),
    };
    let mut paths = e.paths.into_iter();
    if event_type == EventType::Moved {
        return paths
            .next()
            .map(|src| FileEvent {
                event_type,
                src,
                dest: paths.next(),
                timestamp,
            })
            .into_iter()
            .collect();
    }
    paths
        .map(|src| FileEvent {
            event_type,
            src,
            dest: None,
            timestamp,
        })
        .collect()
}

fn queue_event(
    sender: &mpsc::SyncSender<(u64, SystemTime, Event)>,
    revision: u64,
    event: Event,
    health: &WatcherHealth,
) {
    if let Err(mpsc::TrySendError::Full(_)) = sender.try_send((revision, SystemTime::now(), event))
    {
        health.dropped_events.fetch_add(1, Ordering::Relaxed);
        health.degraded.store(true, Ordering::Release);
    }
}

pub fn start_watcher<F>(
    mut config: Config,
    settings: Arc<Mutex<AppSettings>>,
    on_det: F,
) -> NotifyResult<WatcherHandle>
where
    F: Fn(DetectionResult) + Send + Sync + 'static,
{
    if config.test_run_dir.is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Monitoring root cannot be a symbolic link",
        )
        .into());
    }
    std::fs::create_dir_all(&config.test_run_dir)?;
    config.test_run_dir = config.test_run_dir.canonicalize()?;
    CanaryManager.try_deploy(&config.test_run_dir)?;
    let health = Arc::new(WatcherHealth::default());
    let stop = Arc::new(AtomicBool::new(false));
    let quiet = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::sync_channel(EVENT_CAPACITY);
    let callback_health = health.clone();
    let callback_quiet = quiet.clone();
    let callback_settings = settings.clone();
    let mut watcher = recommended_watcher(move |event: NotifyResult<Event>| {
        if callback_quiet.load(Ordering::Acquire) {
            return;
        }
        let current = callback_settings.lock().unwrap_or_else(|e| e.into_inner());
        if !current.monitoring_enabled {
            return;
        }
        let revision = current.revision;
        drop(current);
        match event {
            Ok(event) => {
                tracing::debug!(?event, "Filesystem notification");
                if event.need_rescan() {
                    callback_health.degraded.store(true, Ordering::Release);
                }
                // Queue native events without any disk reads, formatting, or analysis.
                queue_event(&tx, revision, event, &callback_health);
            }
            Err(error) => {
                callback_health.degraded.store(true, Ordering::Release);
                tracing::error!(%error, "Filesystem watcher failed");
            }
        }
    })?;
    watcher.watch(&config.test_run_dir, RecursiveMode::Recursive)?;
    let worker_health = health.clone();
    let worker_stop = stop.clone();
    health.ready.store(true, Ordering::Release);
    let worker = thread::spawn(move || {
        struct WorkerStatus(Arc<WatcherHealth>);
        impl Drop for WorkerStatus {
            fn drop(&mut self) {
                self.0.ready.store(false, Ordering::Release);
                if std::thread::panicking() {
                    self.0.degraded.store(true, Ordering::Release);
                }
            }
        }
        let _status = WorkerStatus(worker_health.clone());
        let mut engine = AiEngine::new(&config);
        let mut previous = AppSettings::default();
        let mut quiet_until = Instant::now();
        while !worker_stop.load(Ordering::Acquire) {
            let (revision, timestamp, event) = match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(event) => event,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if quiet.load(Ordering::Acquire) && Instant::now() >= quiet_until {
                        quiet.store(false, Ordering::Release);
                    }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };
            if quiet.load(Ordering::Acquire) {
                if Instant::now() < quiet_until {
                    continue;
                }
                quiet.store(false, Ordering::Release);
            }
            let current = settings.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if current != previous {
                engine = AiEngine::new(&config);
                previous = current.clone();
            }
            if !current.monitoring_enabled || current.revision != revision {
                continue;
            }
            for file_event in to_events(event, timestamp) {
                if worker_stop.load(Ordering::Acquire) {
                    break;
                }
                let canary = CanaryManager.is_canary(&file_event.src)
                    && matches!(
                        file_event.event_type,
                        EventType::Modified | EventType::Deleted | EventType::Moved
                    );
                let detection = if canary {
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
                        file_path: Some(file_event.src.display().to_string()),
                    }
                } else {
                    if !current.ai_enabled {
                        continue;
                    }
                    let analysis = AnalysisConfig {
                        enable_extensions: current.extension_monitoring,
                        enable_entropy: current.entropy,
                        enable_rate_limit: current.rate_limit,
                        enable_dns: current.dns,
                    };
                    engine.on_event_with_config(&file_event, &analysis);
                    let mut detection = engine.evaluate(&analysis);
                    detection.file_path = Some(file_event.src.display().to_string());
                    detection
                };
                if settings.lock().unwrap_or_else(|e| e.into_inner()).revision != revision {
                    break;
                }
                if detection.level != ThreatLevel::None {
                    crate::demo_log::log_detection(
                        &format!("{:?}", detection.kind),
                        &format!("{:?}", detection.level),
                        detection.confidence,
                        detection.file_path.as_deref(),
                    );
                }
                // Publish before recovery so a demo controller can stop its child promptly.
                on_det(detection.clone());
                if detection.level >= ThreatLevel::High {
                    quiet.store(true, Ordering::Release);
                    crate::demo_log::log_remediation(
                        "THREAT_DETECTED",
                        "Restoring sandbox demo files",
                    );
                    if let Err(error) =
                        crate::simulators::try_cleanup_and_reset_after_ransomware(&config)
                    {
                        worker_health.degraded.store(true, Ordering::Release);
                        tracing::error!(%error, "Automatic demo recovery failed");
                    }
                    engine = AiEngine::new(&config);
                    // Discard pre-recovery events, then suppress delayed native notifications.
                    while rx.try_recv().is_ok() {}
                    quiet_until = Instant::now() + REMEDIATION_QUIET_PERIOD;
                    break;
                }
            }
        }
        worker_health.ready.store(false, Ordering::Release);
    });
    Ok(WatcherHandle {
        watcher: Some(watcher),
        stop,
        worker: Some(worker),
        health,
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
    let handle = start_watcher(config, settings, on_det)?;
    while handle.health.ready.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(250));
    }
    if handle.health.degraded.load(Ordering::Acquire) {
        return Err(notify::Error::generic(
            "Monitoring worker stopped unexpectedly",
        ));
    }
    Ok(())
}

pub fn run_watcher(config: Config) -> NotifyResult<()> {
    run_watcher_with_callback(
        config,
        Arc::new(Mutex::new(AppSettings::default())),
        |det| {
            if det.level != ThreatLevel::None {
                tracing::info!(kind = ?det.kind, level = ?det.level, confidence = det.confidence, "Detection");
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn saturated_queue_is_bounded_and_reports_degraded_monitoring() {
        let (tx, rx) = mpsc::sync_channel(1);
        let health = WatcherHealth::default();
        for _ in 0..100 {
            queue_event(&tx, 0, Event::new(EventKind::Any), &health);
        }
        assert_eq!(rx.try_iter().count(), 1);
        assert_eq!(health.dropped_events.load(Ordering::Relaxed), 99);
        assert!(health.degraded.load(Ordering::Acquire));
    }
}
