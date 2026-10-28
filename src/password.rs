

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};


pub const OTP_LEN: usize = 12;
pub const OTP_VALIDITY_SECS: i64 = 24 * 3600;

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

pub fn hash(password: &str) -> Result<String, String> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub fn verify(password: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}


pub async fn hash_async(password: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || hash(&password))
        .await
        .map_err(|e| e.to_string())?
}

pub async fn verify_async(password: String, phc: String) -> bool {
    tokio::task::spawn_blocking(move || verify(&password, &phc))
        .await
        .unwrap_or(false)
}


pub async fn matches_any_async(password: String, hashes: Vec<String>) -> bool {
    tokio::task::spawn_blocking(move || hashes.iter().any(|h| verify(&password, h)))
        .await
        .unwrap_or(false)
}


pub fn generate_one_time() -> String {
    (0..OTP_LEN)
        .map(|_| ALNUM[rand::random_range(0..ALNUM.len())] as char)
        .collect()
}


pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes[..]);
    hex(&bytes)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

