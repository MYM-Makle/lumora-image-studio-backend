use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::model::{AppError, AppResult};
use axum::http::StatusCode;

pub fn encrypt_secret(key: &[u8; 32], value: &str) -> AppResult<String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "密钥配置无效".into()))?;
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), value.as_bytes())
        .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "凭证加密失败".into()))?;
    let mut payload = nonce_bytes.to_vec();
    payload.extend(encrypted);
    Ok(BASE64.encode(payload))
}

pub fn decrypt_secret(key: &[u8; 32], value: &str) -> AppResult<String> {
    let payload = BASE64
        .decode(value)
        .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "凭证数据无效".into()))?;
    if payload.len() <= 12 {
        return Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "凭证数据无效".into(),
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "密钥配置无效".into()))?;
    let decrypted = cipher
        .decrypt(Nonce::from_slice(&payload[..12]), &payload[12..])
        .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "凭证解密失败".into()))?;
    String::from_utf8(decrypted)
        .map_err(|_| AppError(StatusCode::INTERNAL_SERVER_ERROR, "凭证数据无效".into()))
}

pub fn hash_api_key(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

pub fn mask_key(prefix: &str, suffix: &str) -> String {
    if prefix.is_empty() && suffix.is_empty() {
        "••••••••••••".into()
    } else {
        format!("{prefix}••••••••••••{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_and_hashes_credentials() {
        let key = [9_u8; 32];
        let encrypted = encrypt_secret(&key, "test-secret").unwrap();
        assert_ne!(encrypted, "test-secret");
        assert_eq!(decrypt_secret(&key, &encrypted).unwrap(), "test-secret");
        assert_eq!(hash_api_key("same"), hash_api_key("same"));
        assert_ne!(hash_api_key("same"), hash_api_key("different"));
        let (prefix, suffix) = key_parts("test-key");
        assert_eq!((prefix.as_str(), suffix.as_str()), ("te", "ey"));
        assert!(!mask_key(&prefix, &suffix).contains("test-key"));
    }
}

pub fn key_parts(value: &str) -> (String, String) {
    let chars = value.chars().collect::<Vec<_>>();
    let (prefix_length, suffix_length) = if chars.len() > 13 {
        (9, 4)
    } else if chars.len() > 4 {
        (2, 2)
    } else {
        (0, 0)
    };
    let prefix = chars.iter().take(prefix_length).collect::<String>();
    let suffix = chars
        .iter()
        .rev()
        .take(suffix_length)
        .rev()
        .collect::<String>();
    (prefix, suffix)
}
