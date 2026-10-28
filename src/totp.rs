//! TOTP (RFC 6238) – zadanie dodatkowe. Kody generuje i sprawdza crate `totp-rs`;
//! my dodajemy tylko zapamiętywanie ostatnio użytego kroku, żeby ten sam kod
//! nie zadziałał dwa razy (RFC 6238, §5.2).

use base64::{Engine as _, engine::general_purpose::STANDARD};
use totp_rs::{Builder, Secret, Totp};

/// Nowy sekret (160 bitów) w base32 – tak jak oczekują aplikacje uwierzytelniające.
pub fn new_secret_base32() -> String {
    Secret::generate().to_base32()
}

pub fn build(secret_b32: &str, account: &str) -> Option<Totp> {
    let secret = Secret::try_from_base32(secret_b32).ok()?;
    Builder::new()
        .with_secret(secret)
        .with_issuer(Some("AuthLab"))
        .with_account_name(account)
        .build()
        .ok()
}

/// Sprawdza kod (dopuszczalne ±1 krok = ±30 s). Zwraca numer kroku, jeśli kod
/// jest poprawny i nowszy niż ostatnio użyty, w przeciwnym razie `None`.
pub fn verify(
    secret_b32: &str,
    account: &str,
    code: &str,
    last_step: i64,
    now: i64,
) -> Option<i64> {
    let step = build(secret_b32, account)?.check(code, now.max(0) as u64)? as i64;
    (step > last_step).then_some(step)
}

/// Adres `otpauth://` do zeskanowania w aplikacji uwierzytelniającej.
pub fn otpauth_url(secret_b32: &str, account: &str) -> Option<String> {
    build(secret_b32, account)?.to_url().ok()
}

/// Kod QR jako obrazek SVG w adresie `data:` (generowany lokalnie, bez zewnętrznych usług).
pub fn qr_data_uri(url: &str) -> Option<String> {
    let svg = qrcode::QrCode::new(url.as_bytes())
        .ok()?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(220, 220)
        .build();
    Some(format!(
        "data:image/svg+xml;base64,{}",
        STANDARD.encode(svg)
    ))
}
