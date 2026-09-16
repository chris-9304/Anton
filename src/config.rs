use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Config {
    pub test_run_dir: PathBuf,
    pub time_window_secs: f64,
    pub rename_threshold: usize,
    pub modify_threshold: usize,
    pub shadow_copy_dir: PathBuf,
    pub enable_raptorq: bool,
    pub raptorq_redundancy: u8,
}

impl Config {
    pub fn for_test_run() -> Self {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        Self {
            test_run_dir: manifest_dir.join("TestRun"),
            time_window_secs: 10.0,
            rename_threshold: 8,
            modify_threshold: 15,
            shadow_copy_dir: manifest_dir.join("ShadowCopies"),
            enable_raptorq: true,
            raptorq_redundancy: 3,
        }
    }

    pub fn for_production(base_path: &Path) -> Self {
        Self {
            test_run_dir: base_path.join("Monitored"),
            time_window_secs: 10.0,
            rename_threshold: 8,
            modify_threshold: 15,
            shadow_copy_dir: base_path.join("ShadowCopies"),
            enable_raptorq: true,
            raptorq_redundancy: 3,
        }
    }
}
