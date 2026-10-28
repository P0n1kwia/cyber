use crate::{
    db,
    error::{AppError, AppResult},
    models::{Permission, Role, User, now},
    password::{self, OTP_VALIDITY_SECS},
    session::CurrentUser,
    settings::{self, Settings},
    state::AppState,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use rusqlite::params;
use serde::Deserialize;
use serde_json::{Value, json};

fn valid_username(s: &str) -> bool {
    (3..=32).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn parse_role(s: &str) -> AppResult<Role> {
    Role::parse(s).ok_or_else(|| AppError::bad_request("invalid_role", "Nieznana rola."))
}

fn find(conn: &rusqlite::Connection, id: i64) -> AppResult<User> {
    db::find_user_by_id(conn, id)?.ok_or_else(AppError::not_found)
}

/// Stałe konto ADMIN nie może zostać usunięte, zablokowane, przerobione ani
/// zresetowane przez nikogo (także przez innego administratora).
fn guard_builtin(user: &User) -> AppResult<()> {
    if user.is_builtin {
        return Err(AppError::forbidden(
            "builtin_protected",
            "Stałe konto ADMIN jest chronione przed tą operacją.",
        ));
    }
    Ok(())
}

pub async fn list_users(State(st): State<AppState>, cu: CurrentUser) -> AppResult<Json<Value>> {
    cu.require(Permission::UsersManage)?;
    let users = db::list_users(&st.conn())?;
    Ok(Json(
        json!({ "users": users.iter().map(User::to_json).collect::<Vec<_>>() }),
    ))
}

#[derive(Deserialize)]
pub struct NewUser {
    username: String,
    #[serde(default)]
    full_name: String,
    role: String,
}

/// POST /api/admin/users – tworzy konto z hasłem jednorazowym, które widać tylko w tej odpowiedzi.
pub async fn create_user(
    State(st): State<AppState>,
    cu: CurrentUser,
    Json(req): Json<NewUser>,
) -> AppResult<(StatusCode, Json<Value>)> {
    cu.require(Permission::UsersManage)?;
    let username = req.username.trim().to_string();
    if !valid_username(&username) {
        return Err(AppError::bad_request(
            "invalid_username",
            "Login: 3–32 znaków (litery ASCII, cyfry, . _ -).",
        ));
    }
    let role = parse_role(&req.role)?;
    if db::find_user_by_username(&st.conn(), &username)?.is_some() {
        return Err(AppError::conflict(
            "username_taken",
            "Użytkownik o takim loginie już istnieje.",
        ));
    }

    let one_time = password::generate_one_time();
    let hash = password::hash_async(one_time.clone())
        .await
        .map_err(|_| AppError::internal())?;
    let expires = now() + OTP_VALIDITY_SECS;
    let conn = st.conn();
    let id = db::insert_user(
        &conn,
        &username,
        req.full_name.trim(),
        role,
        &hash,
        expires,
        false,
    )?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "user": find(&conn, id)?.to_json(),
            "one_time_password": one_time,
            "one_time_expires_at": expires,
        })),
    ))
}

#[derive(Deserialize)]
pub struct PatchUser {
    full_name: Option<String>,
    role: Option<String>,
    blocked: Option<bool>,
}

/// PATCH /api/admin/users/{id} – edycja (imię i nazwisko, rola) oraz blokowanie.
pub async fn update_user(
    State(st): State<AppState>,
    cu: CurrentUser,
    Path(id): Path<i64>,
    Json(req): Json<PatchUser>,
) -> AppResult<Json<Value>> {
    cu.require(Permission::UsersManage)?;
    let conn = st.conn();
    let user = find(&conn, id)?;
    if req.role.is_some() || req.blocked.is_some() {
        guard_builtin(&user)?;
    }
    if let Some(name) = &req.full_name {
        conn.execute(
            "UPDATE users SET full_name = ?1 WHERE id = ?2",
            params![name.trim(), id],
        )?;
    }
    if let Some(role) = &req.role {
        conn.execute(
            "UPDATE users SET role = ?1 WHERE id = ?2",
            params![parse_role(role)?.as_str(), id],
        )?;
    }
    if let Some(blocked) = req.blocked {
        // Zablokowany użytkownik traci sesję przy najbliższym żądaniu (patrz session::load_session).
        conn.execute(
            "UPDATE users SET is_blocked = ?1 WHERE id = ?2",
            params![blocked, id],
        )?;
    }
    Ok(Json(json!({ "user": find(&conn, id)?.to_json() })))
}

/// DELETE /api/admin/users/{id} – sesje i historia haseł usuwają się kaskadowo.
pub async fn delete_user(
    State(st): State<AppState>,
    cu: CurrentUser,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    cu.require(Permission::UsersManage)?;
    let conn = st.conn();
    guard_builtin(&find(&conn, id)?)?;
    conn.execute("DELETE FROM users WHERE id = ?1", [id])?;
    Ok(Json(json!({ "ok": true })))
}

/// POST /api/admin/users/{id}/reset-password – nowe hasło jednorazowe (do zmiany przy logowaniu).
pub async fn reset_password(
    State(st): State<AppState>,
    cu: CurrentUser,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    cu.require(Permission::UsersManage)?;
    guard_builtin(&find(&st.conn(), id)?)?;

    let one_time = password::generate_one_time();
    let hash = password::hash_async(one_time.clone())
        .await
        .map_err(|_| AppError::internal())?;
    let expires = now() + OTP_VALIDITY_SECS;
    db::set_password(&st.conn(), id, &hash, true, Some(expires))?;
    Ok(Json(
        json!({ "one_time_password": one_time, "one_time_expires_at": expires }),
    ))
}

pub async fn get_settings(
    State(st): State<AppState>,
    cu: CurrentUser,
) -> AppResult<Json<Settings>> {
    cu.require(Permission::SettingsManage)?;
    Ok(Json(settings::load(&st.conn())?))
}

/// PUT /api/admin/settings – polityka haseł, ważność hasła, czas bezczynności sesji.
pub async fn put_settings(
    State(st): State<AppState>,
    cu: CurrentUser,
    Json(new): Json<Settings>,
) -> AppResult<Json<Settings>> {
    cu.require(Permission::SettingsManage)?;
    let errors = new.validate();
    if !errors.is_empty() {
        return Err(AppError::bad_request("invalid_settings", errors.join(" ")));
    }
    let conn = st.conn();
    settings::save(&conn, &new)?;
    Ok(Json(settings::load(&conn)?))
}
