

use crate::{
    db,
    error::{AppError, AppResult},
    models::now,
    password,
    session::CurrentUser,
    state::AppState,
    totp,
};
use axum::{Json, extract::State};
use rusqlite::params;
use serde::Deserialize;
use serde_json::{Value, json};

fn clean_code(code: &str) -> String {
    code.chars().filter(|c| !c.is_whitespace()).collect()
}

/// POST /api/totp/setup – generuje sekret (jeszcze nieaktywny) i kod QR.
pub async fn totp_setup(State(st): State<AppState>, cu: CurrentUser) -> AppResult<Json<Value>> {
    let user = cu.user();
    if user.totp_enabled {
        return Err(AppError::conflict(
            "totp_already_enabled",
            "Uwierzytelnianie dwuskładnikowe jest już włączone.",
        ));
    }
    let secret = totp::new_secret_base32();
    let url = totp::otpauth_url(&secret, &user.username).ok_or_else(AppError::internal)?;
    let qr = totp::qr_data_uri(&url).ok_or_else(AppError::internal)?;
    st.conn().execute(
        "UPDATE users SET totp_secret = ?1, totp_enabled = 0, totp_last_step = 0 WHERE id = ?2",
        params![secret, user.id],
    )?;
    Ok(Json(json!({ "secret": secret, "qr": qr })))
}

#[derive(Deserialize)]
pub struct CodeReq {
    code: String,
}

/// POST /api/totp/enable – potwierdza konfigurację pierwszym poprawnym kodem.
pub async fn totp_enable(
    State(st): State<AppState>,
    cu: CurrentUser,
    Json(req): Json<CodeReq>,
) -> AppResult<Json<Value>> {
    let conn = st.conn();
    // Świeży odczyt: sekret z /setup został zapisany już po utworzeniu tej sesji.
    let user = db::find_user_by_id(&conn, cu.user().id)?.ok_or_else(AppError::not_found)?;
    let Some(secret) = user.totp_secret.clone().filter(|_| !user.totp_enabled) else {
        return Err(AppError::bad_request(
            "totp_not_started",
            "Najpierw rozpocznij konfigurację TOTP.",
        ));
    };
    match totp::verify(
        &secret,
        &user.username,
        &clean_code(&req.code),
        user.totp_last_step,
        now(),
    ) {
        Some(step) => {
            conn.execute(
                "UPDATE users SET totp_enabled = 1, totp_last_step = ?1 WHERE id = ?2",
                params![step, user.id],
            )?;
            Ok(Json(json!({ "ok": true })))
        }
        None => Err(AppError::bad_request("invalid_totp", "Nieprawidłowy kod.")),
    }
}

#[derive(Deserialize)]
pub struct DisableReq {
    password: String,
    code: String,
}

/// POST /api/totp/disable – wyłączenie wymaga hasła i aktualnego kodu.
pub async fn totp_disable(
    State(st): State<AppState>,
    cu: CurrentUser,
    Json(req): Json<DisableReq>,
) -> AppResult<Json<Value>> {
    let user = cu.user().clone();
    if !password::verify_async(req.password, user.password_hash.clone()).await {
        return Err(AppError::bad_request(
            "invalid_password",
            "Hasło jest niepoprawne.",
        ));
    }
    let conn = st.conn();
    let fresh = db::find_user_by_id(&conn, user.id)?.ok_or_else(AppError::not_found)?;
    let Some(secret) = fresh.totp_secret.clone().filter(|_| fresh.totp_enabled) else {
        return Err(AppError::bad_request(
            "totp_not_enabled",
            "Uwierzytelnianie dwuskładnikowe nie jest włączone.",
        ));
    };
    if totp::verify(
        &secret,
        &fresh.username,
        &clean_code(&req.code),
        fresh.totp_last_step,
        now(),
    )
    .is_none()
    {
        return Err(AppError::bad_request("invalid_totp", "Nieprawidłowy kod."));
    }
    conn.execute(
        "UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_last_step = 0 WHERE id = ?1",
        [user.id],
    )?;
    Ok(Json(json!({ "ok": true })))
}
