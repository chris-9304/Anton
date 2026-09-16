use crate::config::Config;
use rand::Rng;
use rayon::prelude::*;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn seed_test_files(config: &Config) {
    fs::create_dir_all(&config.test_run_dir).ok();
    for i in 0..20 {
        let mut p = config.test_run_dir.clone();
        p.push(format!("doc_{i}.txt"));
        if !p.exists() {
            let mut f = File::create(&p).unwrap();
            writeln!(f, "Important demo document {i}").ok();
        }
    }
}

pub fn run_old_ransomware_demo(config: &Config) {
    println!("[*] Running old-style ransomware demo (slow, classic extensions)...");
    seed_test_files(config);
    let mut files: Vec<PathBuf> = fs::read_dir(&config.test_run_dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.ok()?.path();
            if p.extension().and_then(|s| s.to_str()) == Some("txt") {
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
}

pub fn run_modern_ransomware_demo(config: &Config) {
    println!("[*] Running modern ransomware demo (fast, parallel, .crypt)...");
    seed_test_files(config);
    let files: Vec<PathBuf> = fs::read_dir(&config.test_run_dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.ok()?.path();
            if p.extension().and_then(|s| s.to_str()) == Some("txt") {
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
}

pub fn run_wiper_malware_demo(config: &Config) {
    println!("[*] Running wiper malware demo (mass delete)...");
    seed_test_files(config);
    let files: Vec<PathBuf> = fs::read_dir(&config.test_run_dir)
        .unwrap()
        .filter_map(|e| Some(e.ok()?.path()))
        .collect();
    for p in files {
        let _ = fs::remove_file(&p);
        thread::sleep(Duration::from_millis(50));
    }
    println!("[*] Wiper malware demo completed.");
}

const ENCRYPTED_EXT: &[&str] = &["locked", "crypt", "cordyceps", "zombie"];

fn is_encrypted_ext(ext: &str) -> bool {
    let lower: String = ext.chars().flat_map(|c| c.to_lowercase()).collect();
    ENCRYPTED_EXT.iter().any(|e| *e == lower)
}

pub fn backup_test_run(config: &Config) -> std::io::Result<()> {
    let backup = config
        .test_run_dir
        .parent()
        .unwrap_or_else(|| config.test_run_dir.as_path())
        .join("TestRun_backup");
    if backup.exists() {
        let _ = fs::remove_dir_all(&backup);
    }
    copy_dir_all(&config.test_run_dir, &backup)
}

fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for e in fs::read_dir(src)? {
        let e = e?;
        let p = e.path();
        let name = e.file_name();
        let d = dst.join(&name);
        if p.is_dir() {
            copy_dir_all(&p, &d)?;
        } else {
            let _ = fs::copy(&p, &d);
        }
    }
    Ok(())
}

pub fn revert_demo(config: &Config) {
    let backup = config
        .test_run_dir
        .parent()
        .unwrap_or_else(|| config.test_run_dir.as_path())
        .join("TestRun_backup");
    if backup.exists() {
        if let Ok(entries) = fs::read_dir(&config.test_run_dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_file() {
                    let _ = fs::remove_file(&p);
                }
            }
        }
        let _ = fs::read_dir(&backup).map(|rd| {
            for e in rd.flatten() {
                let from = e.path();
                let name = from.file_name().unwrap();
                let to = config.test_run_dir.join(name);
                if from.is_file() {
                    let _ = fs::copy(&from, &to);
                }
            }
        });
        let _ = fs::remove_dir_all(&backup);
    } else {
        if let Ok(entries) = fs::read_dir(&config.test_run_dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_file() {
                    if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                        if is_encrypted_ext(ext) {
                            let _ = fs::remove_file(&p);
                        }
                    }
                }
            }
        }
        reset_test_run_files(config);
    }
}

pub fn cleanup_and_reset_after_ransomware(config: &Config) {
    fs::create_dir_all(&config.test_run_dir).ok();
    if let Ok(entries) = fs::read_dir(&config.test_run_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                if is_encrypted_ext(ext) {
                    let _ = fs::remove_file(&p);
                }
            }
        }
    }
    reset_test_run_files(config);
}

/// Delete all current files in TestRun and create fresh demo files
/// with mixed types: .txt, .docx, .pptx.
pub fn reset_test_run_files(config: &Config) {
    println!("[*] Resetting TestRun folder with mixed file types...");
    fs::create_dir_all(&config.test_run_dir).ok();

    // Delete existing files (leave directory)
    if let Ok(entries) = fs::read_dir(&config.test_run_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                let _ = fs::remove_file(p);
            }
        }
    }

    // New .txt files
    for i in 0..5 {
        let mut p = config.test_run_dir.clone();
        p.push(format!("report_{i}.txt"));
        let mut f = File::create(&p).unwrap();
        writeln!(f, "Sample text report {i}\nThis is a demo text file.").ok();
    }

    // New .docx-like files (plain text content, demo only)
    for i in 0..5 {
        let mut p = config.test_run_dir.clone();
        p.push(format!("proposal_{i}.docx"));
        let mut f = File::create(&p).unwrap();
        writeln!(f, "Fake DOCX content for proposal {i} (demo only).").ok();
    }

    // New .pptx-like files (plain text content, demo only)
    for i in 0..5 {
        let mut p = config.test_run_dir.clone();
        p.push(format!("slides_{i}.pptx"));
        let mut f = File::create(&p).unwrap();
        writeln!(f, "Fake PPTX content for slide deck {i} (demo only).").ok();
    }

    println!("[*] TestRun folder reset complete.");
}

