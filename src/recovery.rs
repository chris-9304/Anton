use crate::{config::Config, crypto::RaptorQEncoder};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
struct ShadowMetadata {
    original: PathBuf,
    length: u64,
    sha256: Vec<u8>,
}

pub struct RecoveryEngine {
    shadow_dir: PathBuf,
    redundancy: u8,
}

fn digest(path: &Path) -> Result<(u64, Vec<u8>)> {
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 65536];
    let mut hash = Sha256::new();
    let mut length = 0;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
        length += n as u64;
    }
    Ok((length, hash.finalize().to_vec()))
}

fn metadata_path(path: &Path) -> PathBuf {
    path.with_extension("json")
}

impl RecoveryEngine {
    pub fn new(cfg: &Config) -> Self {
        Self {
            shadow_dir: cfg.shadow_copy_dir.clone(),
            redundancy: cfg.raptorq_redundancy,
        }
    }

    pub fn create_shadow_copy(&self, file_path: &Path) -> Result<PathBuf> {
        let original = file_path.canonicalize()?;
        if !fs::symlink_metadata(file_path)?.file_type().is_file() {
            bail!("Shadow source must be a regular file");
        }
        fs::create_dir_all(&self.shadow_dir)?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let shadow = self
            .shadow_dir
            .join(format!("{timestamp}_{}.shadow", rand::random::<u64>()));
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&shadow)?;
        std::io::copy(&mut File::open(&original)?, &mut destination)?;
        destination.sync_all()?;
        let (length, sha256) = digest(&shadow)?;
        if digest(&original)? != (length, sha256.clone()) {
            let _ = fs::remove_file(&shadow);
            bail!("Source changed while creating shadow copy");
        }
        let metadata = ShadowMetadata {
            original,
            length,
            sha256,
        };
        fs::write(metadata_path(&shadow), serde_json::to_vec(&metadata)?)?;
        Ok(shadow)
    }

    pub fn restore_from_shadow(&self, shadow: &Path, target: &Path) -> Result<()> {
        let root = self.shadow_dir.canonicalize()?;
        if !shadow.canonicalize()?.starts_with(&root) {
            bail!("Shadow lies outside configured backup directory");
        }
        let metadata: ShadowMetadata = serde_json::from_slice(&fs::read(metadata_path(shadow))?)?;
        let (length, hash) = digest(shadow)?;
        if length != metadata.length || hash != metadata.sha256 {
            bail!("Shadow failed integrity verification");
        }
        if let Some(parent) = target.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let temporary = target.with_file_name(format!(".anton-restore-{}", rand::random::<u64>()));
        let result = (|| -> Result<()> {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            std::io::copy(&mut File::open(shadow)?, &mut output)?;
            output.sync_all()?;
            drop(output);
            if digest(&temporary)? != (metadata.length, metadata.sha256) {
                bail!("Restored copy failed verification");
            }
            fs::rename(&temporary, target)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    /// Only remove an encrypted file after restoring a verified shadow of its original.
    /// Appended suffixes (report.txt.locked) are unambiguous; replacement suffixes are retained.
    pub fn cleanup_encrypted_files(&self, dir: &Path) -> Result<u32> {
        let mut cleaned = 0;
        for entry in walkdir::WalkDir::new(dir).follow_links(false) {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if !path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
                [
                    "locked",
                    "crypt",
                    "encrypted",
                    "encrypt",
                    "vault",
                    "cordyceps",
                ]
                .iter()
                .any(|known| e.eq_ignore_ascii_case(known))
            }) {
                continue;
            }
            let target = path.with_extension("");
            let target = target
                .parent()
                .unwrap_or(dir)
                .canonicalize()?
                .join(target.file_name().unwrap());
            let mut candidates = Vec::new();
            if !self.shadow_dir.exists() {
                continue;
            }
            for shadow in fs::read_dir(&self.shadow_dir)? {
                let shadow = shadow?.path();
                if shadow.extension().and_then(|e| e.to_str()) != Some("shadow") {
                    continue;
                }
                if let Ok(bytes) = fs::read(metadata_path(&shadow)) {
                    if let Ok(metadata) = serde_json::from_slice::<ShadowMetadata>(&bytes) {
                        if metadata.original == target {
                            candidates.push(shadow);
                        }
                    }
                }
            }
            candidates.sort();
            if let Some(shadow) = candidates.last() {
                self.restore_from_shadow(shadow, &target)?;
                fs::remove_file(path)?;
                cleaned += 1;
            }
        }
        Ok(cleaned)
    }

    pub fn encode_with_raptorq(&self, data: &[u8]) -> Vec<Vec<u8>> {
        RaptorQEncoder::encode(data, self.redundancy)
    }
    pub fn decode_with_raptorq(&self, blocks: &[Vec<u8>], count: usize) -> Result<Vec<u8>> {
        RaptorQEncoder::decode(blocks, count)
    }

    /// Explicit maintenance operation; never scheduled automatically.
    pub fn cleanup_old_shadows(&self, max_age_secs: u64) -> Result<u32> {
        let mut cleaned = 0;
        if !self.shadow_dir.exists() {
            return Ok(0);
        }
        for entry in fs::read_dir(&self.shadow_dir)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if !entry.file_type()?.is_file()
                || entry.path().extension().and_then(|e| e.to_str()) != Some("shadow")
            {
                continue;
            }
            if SystemTime::now()
                .duration_since(metadata.modified()?)
                .unwrap_or_default()
                .as_secs()
                > max_age_secs
            {
                fs::remove_file(entry.path())?;
                let sidecar = metadata_path(&entry.path());
                if sidecar.exists() {
                    fs::remove_file(sidecar)?;
                }
                cleaned += 1;
            }
        }
        Ok(cleaned)
    }
}
