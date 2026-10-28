

use crate::{
    db,
    error::{AppError, AppResult},
    models::{Permission, User, now},
    password::{hex, random_token},
    settings::{self, Settings},
    state::AppState,
};
use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, header, request::Parts},
};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

const COOKIE_NAME: &str = "sid";
pub const PENDING_TOTP_TTL: i64 = 300;
pub const MAX_TOTP_ATTEMPTS: i64 = 5;

pub fn hash_token(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

pub fn token_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    cookies
        .split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE_NAME)
        .map(|(_, value)| value.to_string())
}

pub fn cookie_set(token: &str) -> String {
    format!("{COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/")
}

pub fn cookie_clear() -> String {
    format!("{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

/// Tworzy nową sesję (przy każdym logowaniu nowy token) i zwraca token do ciasteczka.
pub fn create(conn: &Connection, user_id: i64, pending_totp: bool) -> rusqlite::Result<String> {
    let token = random_token();
    let t = now();
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, last_activity, pending_totp) \
         VALUES (?1, ?2, ?3, ?3, ?4)",
        params![hash_token(&token), user_id, t, pending_totp],
    )?;
    Ok(token)
}

pub fn delete(conn: &Connection, token_hash: &str) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM sessions WHERE token_hash = ?1", [token_hash])?;
    Ok(())
}

pub fn needs_password_change(user: &User, settings: &Settings, now: i64) -> bool {
    user.must_change_password
        || (settings.password_max_age_days > 0
            && now - user.password_changed_at > settings.password_max_age_days as i64 * 86_400)
}

pub struct AuthUser {
    pub user: User,
    pub token_hash: String,
    pub needs_password_change: bool,
}

fn unauthenticated() -> AppError {
    AppError::unauthorized("unauthenticated", "Wymagane logowanie.")
}

fn load_session(headers: &HeaderMap, st: &AppState) -> AppResult<AuthUser> {
    let token = token_from_headers(headers).ok_or_else(unauthenticated)?;
    let token_hash = hash_token(&token);
    let t = now();

    let conn = st.conn();
    let cfg = settings::load(&conn)?;

    let row: Option<(i64, i64, bool)> = conn
        .query_row(
            "SELECT user_id, last_activity, pending_totp FROM sessions WHERE token_hash = ?1",
            [&token_hash],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((user_id, last_activity, pending_totp)) = row else {
        return Err(unauthenticated());
    };

    // Logowanie czeka na kod TOTP – to jeszcze nie jest pełna sesja.
    if pending_totp {
        return Err(unauthenticated());
    }

    // Wygaśnięcie po bezczynności.
    if t - last_activity > cfg.session_idle_minutes as i64 * 60 {
        delete(&conn, &token_hash)?;
        return Err(AppError::unauthorized(
            "session_expired",
            "Sesja wygasła z powodu bezczynności. Zaloguj się ponownie.",
        ));
    }


    let user = match db::find_user_by_id(&conn, user_id)? {
        Some(u) if !u.is_blocked => u,
        _ => {
            delete(&conn, &token_hash)?;
            return Err(unauthenticated());
        }
    };

    conn.execute(
        "UPDATE sessions SET last_activity = ?1 WHERE token_hash = ?2",
        params![t, token_hash],
    )?;
    let needs_password_change = needs_password_change(&user, &cfg, t);
    Ok(AuthUser {
        user,
        token_hash,
        needs_password_change,
    })
}


pub struct CurrentUser(pub AuthUser);

/// Zalogowany użytkownik także w trakcie wymuszonej zmiany hasła
/// (używany tylko w /api/me i /api/change-password).
pub struct RestrictedUser(pub AuthUser);

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Self::Rejection> {
        let auth = load_session(&parts.headers, st)?;
        if auth.needs_password_change {
            return Err(AppError::forbidden(
                "password_change_required",
                "Musisz najpierw zmienić hasło.",
            ));
        }
        Ok(CurrentUser(auth))
    }
}

impl FromRequestParts<AppState> for RestrictedUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Self::Rejection> {
        Ok(RestrictedUser(load_session(&parts.headers, st)?))
    }
}

impl CurrentUser {
    pub fn user(&self) -> &User {
        &self.0.user
    }

    /// Sprawdzenie uprawnienia po stronie serwera; brak uprawnienia = 403.
    pub fn require(&self, permission: Permission) -> AppResult<()> {
        if self.user().role.has(permission) {
            Ok(())
        } else {
            Err(AppError::forbidden(
                "forbidden",
                "Brak uprawnień do wykonania tej operacji.",
            ))
        }
    }
}
