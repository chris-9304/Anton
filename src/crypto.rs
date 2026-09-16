use anyhow::{Result, anyhow};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use aes_gcm::{
    aead::OsRng as AesOsRng,
    Aes256Gcm, Nonce as AesNonce,
};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use pbkdf2::pbkdf2_hmac;
use hmac::Hmac;
use std::fs;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid HMAC key length")]
    InvalidKeyLength,
}

pub struct CryptoEngine;

impl CryptoEngine {
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    pub fn is_likely_encrypted(data: &[u8]) -> bool {
        Self::calculate_entropy(data) > 7.5
    }

    pub fn encrypt_aes256gcm(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::{Aead, AeadCore, KeyInit};
        let key_arr: [u8; 32] = key
            .get(..32)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| anyhow!("key must be 32 bytes"))?;
        let key_ref: &aes_gcm::Key<Aes256Gcm> = (&key_arr).into();
        let cipher = Aes256Gcm::new(key_ref);
        let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);
        let ciphertext = cipher.encrypt(&nonce, data).map_err(|e| anyhow!("{}", e))?;
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt_aes256gcm(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::Aead;
        if ciphertext.len() < 12 {
            return Err(anyhow!("Ciphertext too short"));
        }
        let key_arr: [u8; 32] = key
            .get(..32)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| anyhow!("key must be 32 bytes"))?;
        let key_ref: &aes_gcm::Key<Aes256Gcm> = (&key_arr).into();
        let cipher = Aes256Gcm::new(key_ref);
        let nonce = AesNonce::from_slice(&ciphertext[..12]);
        let plaintext = cipher.decrypt(nonce, &ciphertext[12..]).map_err(|e| anyhow!("{}", e))?;
        Ok(plaintext)
    }

    pub fn encrypt_chacha20poly1305(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, data).map_err(|e| anyhow!("{}", e))?;
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt_chacha20poly1305(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(anyhow!("Ciphertext too short"));
        }
        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let plaintext = cipher.decrypt(nonce, &ciphertext[12..]).map_err(|e| anyhow!("{}", e))?;
        Ok(plaintext)
    }

    pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100000, &mut key);
        key
    }

    pub fn compute_hmac(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use hmac::Mac;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    pub fn verify_hmac(data: &[u8], key: &[u8], mac: &[u8]) -> bool {
        match Self::compute_hmac(data, key) {
            Ok(computed) => computed == mac,
            Err(_) => false,
        }
    }

    pub fn generate_rsa_keypair() -> Result<(RsaPrivateKey, RsaPublicKey)> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        let public_key = RsaPublicKey::from(&private_key);
        Ok((private_key, public_key))
    }

    pub fn secure_delete_file(path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let data = fs::read(path)?;
        let mut rng = rand::thread_rng();
        for _ in 0..3 {
            let random_data: Vec<u8> = (0..data.len()).map(|_| rand::random()).collect();
            fs::write(path, &random_data)?;
        }
        fs::remove_file(path)?;
        Ok(())
    }
}

pub struct RaptorQEncoder;

impl RaptorQEncoder {
    pub fn encode(data: &[u8], redundancy: u8) -> Vec<Vec<u8>> {
        let chunk_size = 1024;
        let mut blocks = Vec::new();
        for chunk in data.chunks(chunk_size) {
            blocks.push(chunk.to_vec());
        }
        let original_count = blocks.len();
        for _ in 0..redundancy as usize {
            let parity_block: Vec<u8> = blocks.iter()
                .take(original_count)
                .fold(vec![0u8; chunk_size], |mut acc, block| {
                    for (i, &byte) in block.iter().enumerate() {
                        if i < acc.len() {
                            acc[i] ^= byte;
                        }
                    }
                    acc
                });
            blocks.push(parity_block);
        }
        blocks
    }

    pub fn decode(blocks: &[Vec<u8>], original_count: usize) -> Result<Vec<u8>> {
        if blocks.len() < original_count {
            return Err(anyhow!("Not enough blocks for recovery"));
        }
        let mut result = Vec::new();
        for i in 0..original_count {
            if let Some(block) = blocks.get(i) {
                result.extend_from_slice(block);
            } else {
                return Err(anyhow!("Missing block {}", i));
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_all_zero_buffer_is_zero() {
        let data = vec![0u8; 4096];
        assert_eq!(CryptoEngine::calculate_entropy(&data), 0.0);
    }

    #[test]
    fn entropy_of_uniform_random_like_buffer_is_high() {
        // A buffer containing every possible byte value equally often has maximal
        // (8.0 bits/byte) Shannon entropy -- a good stand-in for "looks encrypted".
        let mut data = Vec::with_capacity(256 * 16);
        for _ in 0..16 {
            for b in 0u8..=255 {
                data.push(b);
            }
        }
        let entropy = CryptoEngine::calculate_entropy(&data);
        assert!(entropy > 7.9, "expected near-maximal entropy, got {}", entropy);
    }

    #[test]
    fn compute_hmac_is_deterministic_and_verifiable() {
        let key = b"a reasonably long test key";
        let data = b"some data to authenticate";
        let mac1 = CryptoEngine::compute_hmac(data, key).expect("hmac should succeed");
        let mac2 = CryptoEngine::compute_hmac(data, key).expect("hmac should succeed");
        assert_eq!(mac1, mac2);
        assert!(CryptoEngine::verify_hmac(data, key, &mac1));
        assert!(!CryptoEngine::verify_hmac(b"different data", key, &mac1));
    }
}
