//! Reproducible detector workload: cargo run --release --no-default-features --example resource_probe
use anton::{
    ai::AiEngine,
    config::Config,
    models::{AnalysisConfig, EventType, FileEvent},
};
use std::{
    path::PathBuf,
    time::{Instant, SystemTime},
};
fn main() {
    let start = Instant::now();
    let mut engine = AiEngine::new(&Config::for_test_run());
    let setup = start.elapsed();
    let timestamp = SystemTime::now();
    let analysis = AnalysisConfig::default();
    for i in 0..20_000 {
        let event = FileEvent {
            event_type: EventType::Created,
            src: PathBuf::from(format!("/anton-probe/folder-{}/file-{i}.txt", i % 100)),
            dest: None,
            timestamp,
        };
        engine.on_event(&event);
        std::hint::black_box(engine.evaluate(&analysis));
    }
    println!(
        "events=20000 setup_ms={} total_ms={}",
        setup.as_millis(),
        start.elapsed().as_millis()
    );
}
