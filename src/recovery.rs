use crate::config::Config;
use crate::crypto::RaptorQEncoder;
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub struct RecoveryEngine {
    shadow_dir: PathBuf,
    redundancy: u8,
}

impl RecoveryEngine {
    pub fn new(cfg: &Config) -> Self {
        std::fs::create_dir_all(&cfg.shadow_copy_dir).ok();
        Self {
            shadow_dir: cfg.shadow_copy_dir.clone(),
            redundancy: cfg.raptorq_redundancy,
        }
    }

    pub fn create_shadow_copy(&self, file_path: &Path) -> Result<PathBuf> {
        if !file_path.exists() {
            return Err(anyhow::anyhow!("File does not exist"));
        }
        let data = fs::read(file_path)?;
        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let file_name = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let shadow_path = self.shadow_dir.join(format!("{}_{}", timestamp, file_name));
        fs::write(&shadow_path, &data)?;
        Ok(shadow_path)
    }

    pub fn restore_from_shadow(&self, shadow_path: &Path, target_path: &Path) -> Result<()> {
        let data = fs::read(shadow_path)?;
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(target_path, &data)?;
        Ok(())
    }

    pub fn cleanup_encrypted_files(&self, dir: &Path) -> Result<u32> {
        let mut cleaned = 0;
        let ransomware_exts = [".locked", ".crypt", ".encrypted", ".encrypt", ".vault"];
        
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if ransomware_exts.iter().any(|&re| ext.eq_ignore_ascii_case(re)) {
                            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                                let original_name = format!("{}.{}", 
                                    stem.rsplit_once('.').map(|x| x.0).unwrap_or(stem),
                                    path.extension().and_then(|e| e.to_str()).unwrap_or("")
                                );
                                let original_path = path.parent().unwrap().join(&original_name);
                                if self.restore_from_shadow(&path, &original_path).is_ok() {
                                    fs::remove_file(&path)?;
                                    cleaned += 1;
                                }
                            }
                        }
                    }
                } else if path.is_dir() {
                    cleaned += self.cleanup_encrypted_files(&path)?;
                }
            }
        }
        Ok(cleaned)
    }

    pub fn encode_with_raptorq(&self, data: &[u8]) -> Vec<Vec<u8>> {
        RaptorQEncoder::encode(data, self.redundancy)
    }

    pub fn decode_with_raptorq(&self, blocks: &[Vec<u8>], original_count: usize) -> Result<Vec<u8>> {
        RaptorQEncoder::decode(blocks, original_count)
    }

    pub fn cleanup_old_shadows(&self, max_age_secs: u64) -> Result<u32> {
        let mut cleaned = 0;
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if self.shadow_dir.is_dir() {
            for entry in fs::read_dir(&self.shadow_dir)? {
                let entry = entry?;
                let path = entry.path();
                if let Ok(metadata) = fs::metadata(&path) {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(age) = modified.duration_since(std::time::UNIX_EPOCH) {
                            if now.saturating_sub(age.as_secs()) > max_age_secs {
                                fs::remove_file(&path)?;
                                cleaned += 1;
                            }
                        }
                    }
                }
            }
        }
        Ok(cleaned)
    }
}
