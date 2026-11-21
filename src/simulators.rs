use crate::canary::CanaryManager;
use crate::config::Config;
use rand::Rng;
use rayon::prelude::*;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum SimulatorError {
    #[error("I/O error during simulation: {0}")]
    Io(#[from] std::io::Error),
}

fn seed_test_files(config: &Config) -> Result<(), SimulatorError> {
    reject_link(&config.test_run_dir)?;
    fs::create_dir_all(&config.test_run_dir)?;
    for i in 0..20 {
        let mut p = config.test_run_dir.clone();
        p.push(format!("doc_{i}.txt"));
        if fs::symlink_metadata(&p).is_err() {
            reject_link(&p)?;
            let mut f = File::create(&p)?;
            writeln!(f, "Important demo document {i}")?;
        }
    }
    Ok(())
}

pub fn run_old_ransomware_demo(config: &Config) -> Result<(), SimulatorError> {
    println!("[*] Running old-style ransomware demo (slow, classic extensions)...");
    seed_test_files(config)?;
    let mut files: Vec<PathBuf> = fs::read_dir(&config.test_run_dir)?
        .filter_map(|e| {
            let p = e.ok()?.path();
            if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_file())
                && p.extension().and_then(|s| s.to_str()) == Some("txt")
            {
                Some(p)
            } else {
                None
            }
        })
        .collect();
    files.sort();
    for p in files {
        let mut enc_path = p.clone();
        enc_path.set_extension("locked");
        let _ = fs::rename(&p, &enc_path);
        thread::sleep(Duration::from_millis(250));
    }
    println!("[*] Old ransomware demo completed.");
    Ok(())
}

pub fn run_modern_ransomware_demo(config: &Config) -> Result<(), SimulatorError> {
    println!("[*] Running modern ransomware demo (fast, parallel, .crypt)...");
    seed_test_files(config)?;
    let files: Vec<PathBuf> = fs::read_dir(&config.test_run_dir)?
        .filter_map(|e| {
            let p = e.ok()?.path();
            if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_file())
                && p.extension().and_then(|s| s.to_str()) == Some("txt")
            {
                Some(p)
            } else {
                None
            }
        })
        .collect();

    files.par_iter().for_each(|p| {
        if let Ok(mut f) = File::create(p) {
            let mut rng = rand::thread_rng();
            let buf: Vec<u8> = (0..2048).map(|_| rng.gen()).collect();
            let _ = f.write_all(&buf);
        }
        let mut enc_path = p.clone();
        enc_path.set_extension("crypt");
        let _ = fs::rename(p, &enc_path);
        thread::sleep(Duration::from_millis(30));
    });
    println!("[*] Modern ransomware demo completed.");
    Ok(())
}

pub fn run_wiper_malware_demo(config: &Config) -> Result<(), SimulatorError> {
    println!("[*] Running wiper malware demo (mass delete)...");
    seed_test_files(config)?;
    let files: Vec<PathBuf> = fs::read_dir(&config.test_run_dir)?
        .filter_map(|e| {
            let e = e.ok()?;
            if e.file_type().ok()?.is_file() {
                Some(e.path())
            } else {
                None
            }
        })
        .collect();
    for p in files {
        let _ = fs::remove_file(&p);
        thread::sleep(Duration::from_millis(50));
    }
    println!("[*] Wiper malware demo completed.");
    Ok(())
}

const ENCRYPTED_EXT: &[&str] = &["locked", "crypt", "cordyceps", "zombie"];

fn is_encrypted_ext(ext: &str) -> bool {
    let lower: String = ext.chars().flat_map(|c| c.to_lowercase()).collect();
    ENCRYPTED_EXT.iter().any(|e| *e == lower)
}

fn backup_path(config: &Config) -> PathBuf {
    config
        .test_run_dir
        .parent()
        .unwrap_or(&config.test_run_dir)
        .join("TestRun_backup")
}

pub fn backup_test_run(config: &Config) -> std::io::Result<()> {
    let backup = backup_path(config);
    if backup.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "A previous backup exists; revert it before starting another demo",
        ));
    }
    reject_link(&config.test_run_dir)?;
    fs::create_dir_all(&config.test_run_dir)?;
    let staging = backup.with_file_name(format!(".anton-backup-{}", rand::random::<u64>()));
    let result =
        copy_dir_all(&config.test_run_dir, &staging).and_then(|()| fs::rename(&staging, &backup));
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn reject_link(path: &std::path::Path) -> std::io::Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Refusing symbolic link: {}", path.display()),
            ));
        }
    }
    Ok(())
}

// Keep verification buffers out of recursive directory frames, including on
// small worker-thread stacks. Publish each destination only after verification.
#[inline(never)]
fn copy_verified_file(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> std::io::Result<()> {
    let temporary = destination.with_file_name(format!(".anton-copy-{}", rand::random::<u64>()));
    let result = (|| -> std::io::Result<()> {
        use std::io::Read;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        std::io::copy(&mut File::open(source)?, &mut output)?;
        output.sync_all()?;
        drop(output);
        let mut left = File::open(source)?;
        let mut right = File::open(&temporary)?;
        let mut a = [0u8; 65536];
        let mut b = [0u8; 65536];
        loop {
            let n = left.read(&mut a)?;
            right.read_exact(&mut b[..n])?;
            if a[..n] != b[..n] {
                return Err(std::io::Error::other("Backup verification failed"));
            }
            if n == 0 {
                break;
            }
        }
        if right.read(&mut b[..1])? != 0 {
            return Err(std::io::Error::other("Backup source changed during copy"));
        }
        fs::set_permissions(&temporary, fs::metadata(source)?.permissions())?;
        fs::rename(&temporary, destination)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    reject_link(src)?;
    reject_link(dst)?;
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let source = entry.path();
        let destination = dst.join(entry.file_name());
        reject_link(&source)?;
        reject_link(&destination)?;
        if entry.file_type()?.is_dir() {
            copy_dir_all(&source, &destination)?;
        } else if entry.file_type()?.is_file() {
            copy_verified_file(&source, &destination)?;
        }
    }
    Ok(())
}

pub fn try_revert_demo(config: &Config) -> std::io::Result<()> {
    let backup = backup_path(config);
    if backup.exists() {
        copy_dir_all(&backup, &config.test_run_dir)?;
        // Remove only sandbox artifacts absent from the verified pre-demo snapshot.
        for entry in walkdir::WalkDir::new(&config.test_run_dir)
            .follow_links(false)
            .contents_first(true)
            .min_depth(1)
        {
            let entry = entry?;
            let relative = entry
                .path()
                .strip_prefix(&config.test_run_dir)
                .map_err(std::io::Error::other)?;
            if !backup.join(relative).exists() {
                if entry.file_type().is_dir() {
                    fs::remove_dir(entry.path())?;
                } else {
                    fs::remove_file(entry.path())?;
                }
            }
        }
        CanaryManager.try_deploy(&config.test_run_dir)?;
        fs::remove_dir_all(&backup)?;
        Ok(())
    } else {
        reset_test_run_files(config).map_err(std::io::Error::other)
    }
}

pub fn revert_demo(config: &Config) {
    if let Err(error) = try_revert_demo(config) {
        tracing::error!(%error, "Demo restore failed; backup retained");
    }
}

pub fn cleanup_and_reset_after_ransomware(config: &Config) {
    if let Err(error) = try_cleanup_and_reset_after_ransomware(config) {
        tracing::error!(%error, "Demo recovery failed");
    }
}

pub fn try_cleanup_and_reset_after_ransomware(config: &Config) -> Result<(), SimulatorError> {
    reject_link(&config.test_run_dir)?;
    fs::create_dir_all(&config.test_run_dir)?;
    for entry in fs::read_dir(&config.test_run_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry
                .path()
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(is_encrypted_ext)
        {
            fs::remove_file(entry.path())?;
        }
    }
    reset_test_run_files(config)
}

/// Delete all current files in TestRun and create fresh demo files
/// with mixed types: .txt, .docx, .pptx.
pub fn reset_test_run_files(config: &Config) -> Result<(), SimulatorError> {
    println!("[*] Resetting TestRun folder with mixed file types...");
    reject_link(&config.test_run_dir)?;
    fs::create_dir_all(&config.test_run_dir)?;

    // Delete existing files (leave directory)
    if let Ok(entries) = fs::read_dir(&config.test_run_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_file()) {
                fs::remove_file(p)?;
            }
        }
    }

    // New .txt files
    for i in 0..5 {
        let mut p = config.test_run_dir.clone();
        p.push(format!("report_{i}.txt"));
        reject_link(&p)?;
        let mut f = File::create(&p)?;
        writeln!(f, "Sample text report {i}\nThis is a demo text file.")?;
    }

    // New .docx-like files (plain text content, demo only)
    for i in 0..5 {
        let mut p = config.test_run_dir.clone();
        p.push(format!("proposal_{i}.docx"));
        reject_link(&p)?;
        let mut f = File::create(&p)?;
        writeln!(f, "Fake DOCX content for proposal {i} (demo only).")?;
    }

    // New .pptx-like files (plain text content, demo only)
    for i in 0..5 {
        let mut p = config.test_run_dir.clone();
        p.push(format!("slides_{i}.pptx"));
        reject_link(&p)?;
        let mut f = File::create(&p)?;
        writeln!(f, "Fake PPTX content for slide deck {i} (demo only).")?;
    }

    // Reset deletes everything in TestRun, including the honeytoken canary files
    // deployed at watcher startup -- redeploy them so honeytoken detection keeps
    // working for the rest of the session instead of silently going dark after the
    // first remediation cycle.
    CanaryManager.try_deploy(&config.test_run_dir)?;

    println!("[*] TestRun folder reset complete.");
    Ok(())
}
