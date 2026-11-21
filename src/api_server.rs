use anton::app_settings::AppSettings;
use anton::config::Config;
use anton::models::{DetectionResult, ScanRecord, ThreatLevel};
use anton::watcher::{start_watcher, WatcherHealth};
use axum::{
    extract::State,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::collections::VecDeque;
use std::sync::{atomic::Ordering, Arc, Mutex};
use tower_http::{catch_panic::CatchPanicLayer, cors::CorsLayer};

#[derive(Default)]
struct Activity {
    scan_count: u64,
    threats_blocked: u64,
    logs: VecDeque<String>,
    scans: VecDeque<ScanRecord>,
    detections: VecDeque<DetectionResult>,
}

fn retain_latest<T>(queue: &mut VecDeque<T>, value: T, capacity: usize) {
    if queue.len() >= capacity {
        queue.pop_front();
    }
    queue.push_back(value);
}

impl Activity {
    fn record_scan(&mut self, scan_type: &str, result: String, threats_found: u32) -> u64 {
        self.scan_count += 1;
        let record = ScanRecord {
            id: self.scan_count,
            scan_type: scan_type.into(),
            result,
            timestamp: chrono::Local::now().to_rfc3339(),
            threats_found,
        };
        retain_latest(&mut self.scans, record, 1000);
        self.scan_count
    }

    fn record_detection(&mut self, detection: DetectionResult) {
        let line = format!(
            "[{}] {:?} {:?} conf={:.0}%",
            chrono::Local::now().format("%H:%M:%S"),
            detection.kind,
            detection.level,
            detection.confidence * 100.0
        );
        retain_latest(&mut self.logs, line, 100);
        if detection.level >= ThreatLevel::High {
            self.threats_blocked += 1;
            self.record_scan("Auto-scan", format!("Detected {:?}", detection.kind), 1);
        }
        retain_latest(&mut self.detections, detection, 50);
    }
}

#[derive(Clone)]
struct AppState {
    settings: Arc<Mutex<AppSettings>>,
    activity: Arc<Mutex<Activity>>,
    health: Arc<WatcherHealth>,
}

#[derive(Deserialize)]
struct ToggleRequest {
    enabled: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let settings = Arc::new(Mutex::new(AppSettings::default()));
    let activity = Arc::new(Mutex::new(Activity::default()));
    let callback_activity = activity.clone();
    let mut watcher = start_watcher(Config::for_test_run(), settings.clone(), move |detection| {
        callback_activity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_detection(detection);
    })?;
    let state = AppState {
        settings,
        activity,
        health: watcher.health.clone(),
    };
    let address = std::env::var("ANTON_API_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!(address = %listener.local_addr()?, "Anton API server running");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(%error, "Shutdown signal failed");
            }
        })
        .await?;
    watcher.stop();
    Ok(())
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/status", get(get_status))
        .route("/api/detections", get(get_detections))
        .route("/api/logs", get(get_logs))
        .route("/api/scans", get(get_scans))
        .route("/api/settings/ai", post(toggle_ai))
        .route("/api/settings/monitoring", post(toggle_monitoring))
        .route("/api/scan/quick", post(quick_scan))
        .route("/api/scan/full", post(full_scan))
        .layer(CatchPanicLayer::new())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn get_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let (scan_count, threats_blocked) = {
        let activity = state.activity.lock().unwrap_or_else(|e| e.into_inner());
        (activity.scan_count, activity.threats_blocked)
    };
    let health = if !state.health.ready.load(Ordering::Acquire) {
        "stopped"
    } else if state.health.degraded.load(Ordering::Acquire) {
        "degraded"
    } else if !settings.monitoring_enabled {
        "paused"
    } else {
        "ready"
    };
    Json(serde_json::json!({
        "ai_enabled": settings.ai_enabled, "monitoring_enabled": settings.monitoring_enabled,
        "scan_count": scan_count, "threats_blocked": threats_blocked,
        "files_monitored": 1200000, "heuristic_score": 98,
        "demo_mode": true, "monitoring_health": health,
        "dropped_events": state.health.dropped_events.load(Ordering::Relaxed),
    }))
}

async fn get_detections(State(state): State<AppState>) -> Json<serde_json::Value> {
    let snapshot: Vec<_> = state
        .activity
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .detections
        .iter()
        .rev()
        .take(20)
        .cloned()
        .collect();
    Json(serde_json::json!({ "detections": snapshot }))
}

async fn get_logs(State(state): State<AppState>) -> Json<serde_json::Value> {
    let snapshot: Vec<_> = state
        .activity
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .logs
        .iter()
        .rev()
        .take(50)
        .cloned()
        .collect();
    Json(serde_json::json!({ "logs": snapshot }))
}

async fn get_scans(State(state): State<AppState>) -> Json<serde_json::Value> {
    let snapshot: Vec<_> = state
        .activity
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .scans
        .iter()
        .rev()
        .cloned()
        .collect();
    Json(serde_json::json!({ "scans": snapshot }))
}

async fn toggle_ai(
    State(state): State<AppState>,
    Json(request): Json<ToggleRequest>,
) -> Json<serde_json::Value> {
    state
        .settings
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .set_from_name("ai", request.enabled);
    Json(serde_json::json!({ "success": true, "ai_enabled": request.enabled }))
}

async fn toggle_monitoring(
    State(state): State<AppState>,
    Json(request): Json<ToggleRequest>,
) -> Json<serde_json::Value> {
    state
        .settings
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .set_from_name("monitoring", request.enabled);
    Json(serde_json::json!({ "success": true, "monitoring_enabled": request.enabled }))
}

async fn quick_scan(State(state): State<AppState>) -> Json<serde_json::Value> {
    demo_scan(&state, "Quick scan")
}
async fn full_scan(State(state): State<AppState>) -> Json<serde_json::Value> {
    demo_scan(&state, "Full scan")
}

fn demo_scan(state: &AppState, kind: &str) -> Json<serde_json::Value> {
    let id = state
        .activity
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .record_scan(kind, "Demo only — no files scanned".into(), 0);
    Json(serde_json::json!({ "success": true, "scan_id": id, "demo_mode": true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AppState {
        AppState {
            settings: Arc::new(Mutex::new(AppSettings::default())),
            activity: Arc::new(Mutex::new(Activity::default())),
            health: Arc::new(WatcherHealth::default()),
        }
    }

    #[tokio::test]
    async fn toggles_update_watcher_settings_and_status() {
        let state = state();
        let _ = toggle_ai(State(state.clone()), Json(ToggleRequest { enabled: false })).await;
        let _ =
            toggle_monitoring(State(state.clone()), Json(ToggleRequest { enabled: false })).await;
        let status = get_status(State(state.clone())).await.0;
        assert_eq!(status["ai_enabled"], false);
        assert_eq!(status["monitoring_enabled"], false);
        assert_eq!(state.settings.lock().unwrap().revision, 2);
    }

    #[test]
    fn history_is_bounded_and_ids_remain_cumulative() {
        let state = state();
        for _ in 0..1500 {
            let _ = demo_scan(&state, "Quick scan");
        }
        let activity = state.activity.lock().unwrap();
        assert_eq!(activity.scans.len(), 1000);
        assert_eq!(activity.scans.front().unwrap().id, 501);
        assert_eq!(activity.scan_count, 1500);
        let record = serde_json::to_value(activity.scans.back().unwrap()).unwrap();
        assert_eq!(record["type"], "Quick scan");
    }
}
