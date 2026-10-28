use crate::{
    db,
    error::{AppError, AppResult},
    models::now,
    password, policy,
    session::{self, RestrictedUser},
    settings,
    state::AppState,
    totp,
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
pub struct LoginReq {
    username: String,
    password: String,
}

/// POST /api/login – identyfikacja (login) i uwierzytelnienie (hasło).
pub async fn login(State(st): State<AppState>, Json(req): Json<LoginReq>) -> AppResult<Response> {
    let user = db::find_user_by_username(&st.conn(), req.username.trim())?;

    let password_ok = match &user {
        Some(u) => password::verify_async(req.password, u.password_hash.clone()).await,
        None => false,
    };

    // Ten sam komunikat dla nieistniejącego loginu i błędnego hasła.
    let Some(user) = user.filter(|_| password_ok) else {
        return Err(AppError::unauthorized(
            "invalid_credentials",
            "Login lub hasło niepoprawne",
        ));
    };

    // Poniższe komunikaty zobaczy tylko ktoś, kto podał poprawne hasło.
    if user.is_blocked {
        return Err(AppError::forbidden(
            "account_blocked",
            "Konto jest zablokowane. Skontaktuj się z administratorem.",
        ));
    }
    let t = now();
    if user.one_time_expires_at.is_some_and(|expires| t > expires) {
        return Err(AppError::forbidden(
            "one_time_expired",
            "Hasło jednorazowe wygasło. Poproś administratora o nowe.",
        ));
    }

    let conn = st.conn();
    let cfg = settings::load(&conn)?;
    let token = session::create(&conn, user.id, user.totp_enabled)?;
    Ok((
        [(header::SET_COOKIE, session::cookie_set(&token))],
        Json(json!({
            "status": if user.totp_enabled { "totp_required" } else { "ok" },
            "must_change_password": session::needs_password_change(&user, &cfg, t),
        })),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct TotpReq {
    code: String,
}

/// POST /api/login/totp – drugi krok logowania: kod z aplikacji.
pub async fn login_totp(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<TotpReq>,
) -> AppResult<Json<Value>> {
    let unauthenticated = || AppError::unauthorized("unauthenticated", "Wymagane logowanie.");
    let token = session::token_from_headers(&headers).ok_or_else(unauthenticated)?;
    let token_hash = session::hash_token(&token);
    let t = now();

    let conn = st.conn();
    let row: Option<(i64, i64, bool, i64)> = conn
        .query_row(
            "SELECT user_id, created_at, pending_totp, totp_attempts FROM sessions WHERE token_hash = ?1",
            [&token_hash],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((user_id, created_at, pending, attempts)) = row else {
        return Err(unauthenticated());
    };
    if !pending || t - created_at > session::PENDING_TOTP_TTL {
        session::delete(&conn, &token_hash)?;
        return Err(unauthenticated());
    }
    let (user, secret) = match db::find_user_by_id(&conn, user_id)? {
        Some(u) if !u.is_blocked && u.totp_enabled && u.totp_secret.is_some() => {
            let secret = u.totp_secret.clone().unwrap();
            (u, secret)
        }
        _ => {
            session::delete(&conn, &token_hash)?;
            return Err(unauthenticated());
        }
    };

    let code: String = req.code.chars().filter(|c| !c.is_whitespace()).collect();
    match totp::verify(&secret, &user.username, &code, user.totp_last_step, t) {
        Some(step) => {
            conn.execute(
                "UPDATE users SET totp_last_step = ?1 WHERE id = ?2",
                rusqlite::params![step, user.id],
            )?;
            conn.execute(
                "UPDATE sessions SET pending_totp = 0, last_activity = ?1 WHERE token_hash = ?2",
                rusqlite::params![t, token_hash],
            )?;
            let cfg = settings::load(&conn)?;
            Ok(Json(json!({
                "status": "ok",
                "must_change_password": session::needs_password_change(&user, &cfg, t),
            })))
        }
        None if attempts + 1 >= session::MAX_TOTP_ATTEMPTS => {
            session::delete(&conn, &token_hash)?; // po 5 błędach trzeba zacząć od hasła
            Err(AppError::unauthorized(
                "too_many_totp",
                "Zbyt wiele błędnych kodów. Zaloguj się ponownie.",
            ))
        }
        None => {
            conn.execute(
                "UPDATE sessions SET totp_attempts = totp_attempts + 1 WHERE token_hash = ?1",
                [&token_hash],
            )?;
            Err(AppError::unauthorized("invalid_totp", "Nieprawidłowy kod."))
        }
    }
}

/// POST /api/logout – usuwa sesję z bazy, więc token przestaje działać.
pub async fn logout(State(st): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    if let Some(token) = session::token_from_headers(&headers) {
        session::delete(&st.conn(), &session::hash_token(&token))?;
    }
    Ok((
        [(header::SET_COOKIE, session::cookie_clear())],
        Json(json!({ "ok": true })),
    )
        .into_response())
}

/// GET /api/me – kim jestem, jakie mam uprawnienia i czy muszę zmienić hasło.
pub async fn me(RestrictedUser(auth): RestrictedUser) -> Json<Value> {
    let user = &auth.user;
    let permissions: Vec<&str> = user.role.permissions().iter().map(|p| p.as_str()).collect();
    Json(json!({
        "username": user.username,
        "full_name": user.full_name,
        "role": user.role.as_str(),
        "permissions": permissions,
        "must_change_password": auth.needs_password_change,
        "totp_enabled": user.totp_enabled,
    }))
}

#[derive(Deserialize)]
pub struct ChangePasswordReq {
    old_password: String,
    new_password: String,
    new_password_confirm: String,
}

/// POST /api/change-password – zmiana hasła, także wymuszona przy pierwszym logowaniu.
/// Wymaga starego hasła; nowe musi spełniać politykę i różnić się od wszystkich poprzednich.
pub async fn change_password(
    State(st): State<AppState>,
    RestrictedUser(auth): RestrictedUser,
    Json(req): Json<ChangePasswordReq>,
) -> AppResult<Json<Value>> {
    let user = auth.user;

    if req.new_password != req.new_password_confirm {
        return Err(AppError::bad_request(
            "mismatch",
            "Nowe hasła nie są identyczne.",
        ));
    }
    if !password::verify_async(req.old_password, user.password_hash.clone()).await {
        return Err(AppError::bad_request(
            "invalid_old_password",
            "Obecne hasło jest niepoprawne.",
        ));
    }

    // Polityka haseł z aktualnych ustawień (admin może je zmieniać w trakcie pracy).
    let (cfg, history) = {
        let conn = st.conn();
        (
            settings::load(&conn)?,
            db::password_history(&conn, user.id)?,
        )
    };
    let violations = policy::validate(&req.new_password, &user.username, &cfg);
    if !violations.is_empty() {
        return Err(
            AppError::bad_request("weak_password", "Hasło nie spełnia wymagań polityki.")
                .with_extra(json!({ "violations": violations })),
        );
    }

    // Historia zawiera też hasło aktualne, więc nowe musi się różnić od każdego dotychczasowego.
    if password::matches_any_async(req.new_password.clone(), history).await {
        return Err(AppError::bad_request(
            "password_reused",
            "Nowe hasło musi różnić się od poprzednich haseł.",
        ));
    }

    let new_hash = password::hash_async(req.new_password).await.map_err(|e| {
        eprintln!("błąd hashowania: {e}");
        AppError::internal()
    })?;
    db::set_password(&st.conn(), user.id, &new_hash, false, None)?;
    Ok(Json(json!({ "ok": true })))
}
