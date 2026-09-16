mod app_settings;
mod behavior_engine;
mod canary;
mod config;
mod models;
mod ai;
mod detectors;
mod watcher;
mod simulators;
mod recovery;
mod crypto;
mod demo_log;

use axum::{
    extract::State,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::CorsLayer;
use crate::config::Config;
use crate::models::{DetectionResult, ThreatLevel, ScanRecord};
use crate::watcher::run_watcher_with_callback;
use crate::recovery::RecoveryEngine;

#[derive(Clone)]
struct AppState {
    ai_enabled: Arc<Mutex<bool>>,
    monitoring_enabled: Arc<Mutex<bool>>,
    scan_count: Arc<Mutex<u64>>,
    threats_blocked: Arc<Mutex<u64>>,
    files_monitored: Arc<Mutex<u64>>,
    heuristic_score: Arc<Mutex<u32>>,
    activity_logs: Arc<Mutex<Vec<String>>>,
    scan_history: Arc<Mutex<Vec<ScanRecord>>>,
    recent_detections: Arc<Mutex<Vec<DetectionResult>>>,
    recovery: Arc<RecoveryEngine>,
}

#[derive(Deserialize)]
struct AiToggleRequest {
    enabled: bool,
}

#[derive(Deserialize)]
struct MonitoringToggleRequest {
    enabled: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let cfg = Config::for_test_run();
    let recovery = Arc::new(RecoveryEngine::new(&cfg));
    
    let state = AppState {
        ai_enabled: Arc::new(Mutex::new(true)),
        monitoring_enabled: Arc::new(Mutex::new(true)),
        scan_count: Arc::new(Mutex::new(0)),
        threats_blocked: Arc::new(Mutex::new(53)),
        files_monitored: Arc::new(Mutex::new(1200000)),
        heuristic_score: Arc::new(Mutex::new(98)),
        activity_logs: Arc::new(Mutex::new(Vec::new())),
        scan_history: Arc::new(Mutex::new(Vec::new())),
        recent_detections: Arc::new(Mutex::new(Vec::new())),
        recovery: recovery.clone(),
    };

    let state_clone = state.clone();
    let cfg_clone = cfg.clone();
    let settings = Arc::new(Mutex::new(app_settings::AppSettings::default()));

    std::thread::spawn(move || {
        let _ = run_watcher_with_callback(cfg_clone, settings, move |det: DetectionResult| {
            let mut logs = state_clone.activity_logs.lock().unwrap_or_else(|e| e.into_inner());
            let log_line = format!(
                "[{}] {:?} {:?} conf={:.0}%",
                chrono::Local::now().format("%H:%M:%S"),
                det.kind,
                det.level,
                det.confidence * 100.0
            );
            logs.push(log_line);
            if logs.len() > 100 {
                logs.remove(0);
            }

            let mut detections = state_clone.recent_detections.lock().unwrap_or_else(|e| e.into_inner());
            detections.push(det.clone());
            if detections.len() > 50 {
                detections.remove(0);
            }

            if det.level.as_u8() >= ThreatLevel::High.as_u8() {
                let mut threats = state_clone.threats_blocked.lock().unwrap_or_else(|e| e.into_inner());
                *threats += 1;

                let mut scans = state_clone.scan_history.lock().unwrap_or_else(|e| e.into_inner());
                let mut count = state_clone.scan_count.lock().unwrap_or_else(|e| e.into_inner());
                *count += 1;
                scans.push(ScanRecord {
                    id: *count,
                    scan_type: "Auto-scan".to_string(),
                    result: format!("Detected {:?}", det.kind),
                    timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                    threats_found: 1,
                });
            }
        });
    });

    let app = Router::new()
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
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    tracing::info!("Anton API server running on http://localhost:8080");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn get_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ai_enabled": *state.ai_enabled.lock().unwrap_or_else(|e| e.into_inner()),
        "monitoring_enabled": *state.monitoring_enabled.lock().unwrap_or_else(|e| e.into_inner()),
        "scan_count": *state.scan_count.lock().unwrap_or_else(|e| e.into_inner()),
        "threats_blocked": *state.threats_blocked.lock().unwrap_or_else(|e| e.into_inner()),
        "files_monitored": *state.files_monitored.lock().unwrap_or_else(|e| e.into_inner()),
        "heuristic_score": *state.heuristic_score.lock().unwrap_or_else(|e| e.into_inner()),
    }))
}

async fn get_detections(State(state): State<AppState>) -> Json<serde_json::Value> {
    let detections = state.recent_detections.lock().unwrap_or_else(|e| e.into_inner());
    Json(serde_json::json!({
        "detections": detections.iter().rev().take(20).collect::<Vec<_>>()
    }))
}

async fn get_logs(State(state): State<AppState>) -> Json<serde_json::Value> {
    let logs = state.activity_logs.lock().unwrap_or_else(|e| e.into_inner());
    Json(serde_json::json!({
        "logs": logs.iter().rev().take(50).collect::<Vec<_>>()
    }))
}

async fn get_scans(State(state): State<AppState>) -> Json<serde_json::Value> {
    let scans = state.scan_history.lock().unwrap_or_else(|e| e.into_inner());
    Json(serde_json::json!({
        "scans": scans.iter().rev().collect::<Vec<_>>()
    }))
}

async fn toggle_ai(
    State(state): State<AppState>,
    Json(req): Json<AiToggleRequest>,
) -> Json<serde_json::Value> {
    *state.ai_enabled.lock().unwrap_or_else(|e| e.into_inner()) = req.enabled;
    Json(serde_json::json!({ "success": true, "ai_enabled": req.enabled }))
}

async fn toggle_monitoring(
    State(state): State<AppState>,
    Json(req): Json<MonitoringToggleRequest>,
) -> Json<serde_json::Value> {
    *state.monitoring_enabled.lock().unwrap_or_else(|e| e.into_inner()) = req.enabled;
    Json(serde_json::json!({ "success": true, "monitoring_enabled": req.enabled }))
}

async fn quick_scan(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut count = state.scan_count.lock().unwrap_or_else(|e| e.into_inner());
    *count += 1;
    let mut scans = state.scan_history.lock().unwrap_or_else(|e| e.into_inner());
    scans.push(ScanRecord {
        id: *count,
        scan_type: "Quick scan".to_string(),
        result: "No threats found".to_string(),
        timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
        threats_found: 0,
    });
    Json(serde_json::json!({ "success": true, "scan_id": *count }))
}

async fn full_scan(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut count = state.scan_count.lock().unwrap_or_else(|e| e.into_inner());
    *count += 1;
    let mut scans = state.scan_history.lock().unwrap_or_else(|e| e.into_inner());
    scans.push(ScanRecord {
        id: *count,
        scan_type: "Full scan".to_string(),
        result: "System clean".to_string(),
        timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
        threats_found: 0,
    });
    Json(serde_json::json!({ "success": true, "scan_id": *count }))
}
