use crate::config::Config;
use crate::detectors::{
    file_event_to_op, on_file_event, BehaviorAnalyzer, EntropyAnalyzer, ExtensionAnalyzer,
    FrequencyAnalyzer, NetworkAnalyzer,
};
use crate::models::{
    AnalysisConfig, DetectionResult, DetectionSignals, FileEvent, ThreatKind, ThreatLevel,
};
use crate::behavior_engine::BehaviorEngine;
use std::fs::File;
use std::io::Read;

const ENTROPY_HEADER_BYTES: usize = 4096;

pub struct AiEngine {
    freq: FrequencyAnalyzer,
    ext: ExtensionAnalyzer,
    beh: BehaviorAnalyzer,
    ent: EntropyAnalyzer,
    _network: NetworkAnalyzer,
    behavior_engine: BehaviorEngine,
    last_behavior_threat: Option<ThreatLevel>,
    enabled: bool,
}

impl AiEngine {
    pub fn new(cfg: &Config) -> Self {
        Self {
            freq: FrequencyAnalyzer::new(),
            ext: ExtensionAnalyzer::new(5, cfg.time_window_secs),
            beh: BehaviorAnalyzer::new(cfg.time_window_secs),
            ent: EntropyAnalyzer::new(cfg.time_window_secs),
            _network: NetworkAnalyzer::new(),
            behavior_engine: BehaviorEngine::new(),
            last_behavior_threat: None,
            enabled: true,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn on_event(&mut self, ev: &FileEvent) {
        if !self.enabled {
            return;
        }
        self.freq.push(ev);
        self.ext.push(ev);
        self.beh.push(ev);

        // Read the file's header once and share it between EntropyAnalyzer and the
        // behavior engine below, instead of each doing its own independent open+read
        // of the same file for the same event.
        let mut header_buf = vec![0u8; ENTROPY_HEADER_BYTES];
        let header_len = if ev.event_type == crate::models::EventType::Modified {
            File::open(&ev.src)
                .ok()
                .and_then(|mut f| f.read(&mut header_buf).ok())
                .unwrap_or(0)
        } else {
            0
        };
        let header: Option<&[u8]> = if header_len > 0 { Some(&header_buf[..header_len]) } else { None };
        self.ent.push(ev, header);

        // Feed into Owlyshield-like behavior engine (pid=0 when watcher doesn't provide it).
        let entropy = match header {
            Some(h) => crate::crypto::CryptoEngine::calculate_entropy(h) as f32,
            None => 0.0,
        };
        let op = file_event_to_op(ev, entropy);
        let level = on_file_event(
            &mut self.behavior_engine,
            0,
            &ev.src,
            entropy,
            op,
        );
        if level != ThreatLevel::None {
            self.last_behavior_threat = Some(level);
        }
    }

    pub fn evaluate(&mut self, config: &AnalysisConfig) -> DetectionResult {
        if !self.enabled {
            return DetectionResult {
                kind: ThreatKind::Benign,
                level: ThreatLevel::None,
                confidence: 0.0,
                signals: DetectionSignals {
                    frequency_score: 0.0,
                    extension_score: 0.0,
                    behavior_score: 0.0,
                    entropy_score: 0.0,
                },
                timestamp: chrono::Local::now().to_rfc3339(),
                file_path: None,
            };
        }

        // Owlyshield behavioral layer: coordinated attack (traversal + entropy) -> Critical.
        if self.last_behavior_threat == Some(ThreatLevel::Critical) {
            self.last_behavior_threat = None;
            return DetectionResult {
                kind: ThreatKind::RansomwareTraverser,
                level: ThreatLevel::Critical,
                confidence: 0.95,
                signals: DetectionSignals {
                    frequency_score: 0.0,
                    extension_score: 0.0,
                    behavior_score: 1.0,
                    entropy_score: 0.9,
                },
                timestamp: chrono::Local::now().to_rfc3339(),
                file_path: None,
            };
        }
        if self.last_behavior_threat == Some(ThreatLevel::High) {
            self.last_behavior_threat = None;
        }

        let signals = DetectionSignals {
            frequency_score: self.freq.frequency_score(config),
            extension_score: self.ext.extension_score(config),
            behavior_score: self.beh.automation_score(),
            entropy_score: self.ent.entropy_score(config),
        };

        let mut confidence = 0.0f32;
        let mut kind = ThreatKind::Benign;

        let freq = signals.frequency_score;
        let ext = signals.extension_score;
        let beh = signals.behavior_score;
        let ent = signals.entropy_score;

        let rename_burst = self.freq.rename_burst();
        let modify_burst = self.freq.modify_burst();
        let delete_burst = self.freq.delete_burst();

        // 4-layer combo: Entropy > 0.9 AND Frequency > 0.8 -> High Threat (Ransomware / encryption storm)
        if ent > 0.9 && freq > 0.8 {
            kind = ThreatKind::HighEntropyStorm;
            confidence = 0.95;
        } else if delete_burst && ext < 0.3 {
            kind = ThreatKind::WiperMalware;
            confidence = 0.75 + (delete_burst as u32 as f32 * 0.05).min(0.2);
        } else if ext > 0.9 && freq > 0.4 && beh > 0.3 && rename_burst {
            kind = ThreatKind::RansomwareOld;
            confidence = 0.7 * ext + 0.2 * freq + 0.1 * beh;
        } else if freq > 0.9 && ext > 0.7 && beh > 0.6 && (rename_burst || modify_burst) {
            kind = ThreatKind::RansomwareModern;
            confidence = 0.3 * ext + 0.4 * freq + 0.3 * beh;
            if ent > 0.7 {
                confidence = confidence.max(0.85);
            }
        } else if freq > 0.8 && ent > 0.7 {
            kind = ThreatKind::RansomwareTraverser;
            confidence = 0.85;
        }

        if confidence < 0.2 {
            kind = ThreatKind::Benign;
            confidence = 0.0;
        }

        let level = if confidence >= 0.9 {
            ThreatLevel::Critical
        } else if confidence >= 0.75 {
            ThreatLevel::High
        } else if confidence >= 0.5 {
            ThreatLevel::Medium
        } else if confidence >= 0.25 {
            ThreatLevel::Low
        } else {
            ThreatLevel::None
        };

        DetectionResult {
            kind,
            level,
            confidence,
            signals,
            timestamp: chrono::Local::now().to_rfc3339(),
            file_path: None,
        }
    }
}
