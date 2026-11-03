use crate::models::{Role, USER_COLS, User, now};
use rusqlite::{Connection, OptionalExtension, params};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS users (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    username              TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    full_name             TEXT    NOT NULL DEFAULT '',
    role                  TEXT    NOT NULL CHECK (role IN ('Administrator','Redaktor','Czytelnik')),
    password_hash         TEXT    NOT NULL,           -- Argon2id (PHC: parametry + sól + hash)
    password_changed_at   INTEGER NOT NULL,
    must_change_password  INTEGER NOT NULL DEFAULT 1,
    one_time_expires_at   INTEGER,                    -- NULL = hasło stałe
    is_blocked            INTEGER NOT NULL DEFAULT 0,
    is_builtin            INTEGER NOT NULL DEFAULT 0, -- stałe konto ADMIN
    totp_secret           TEXT,
    totp_enabled          INTEGER NOT NULL DEFAULT 0,
    totp_last_step        INTEGER NOT NULL DEFAULT 0,
    failed_attempts       INTEGER NOT NULL DEFAULT 0, -- kolejne błędne logowania (zerowane po sukcesie lub blokadzie)
    locked_until          INTEGER NOT NULL DEFAULT 0  -- do kiedy konto jest zablokowane czasowo (unix, 0 = nie)
);

CREATE TABLE IF NOT EXISTS password_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash     TEXT    PRIMARY KEY,               -- SHA-256 tokenu z ciasteczka
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at     INTEGER NOT NULL,
    last_activity  INTEGER NOT NULL,
    pending_totp   INTEGER NOT NULL DEFAULT 0,        -- hasło OK, czeka na kod TOTP
    totp_attempts  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS articles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT    NOT NULL,
    body        TEXT    NOT NULL,
    author_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at  INTEGER NOT NULL
);
";

pub fn open(path: &str) -> rusqlite::Result<Connection> {
    init(Connection::open(path)?)
}

pub fn open_in_memory() -> rusqlite::Result<Connection> {
    init(Connection::open_in_memory()?)
}

fn init(conn: Connection) -> rusqlite::Result<Connection> {
    conn.pragma_update(None, "foreign_keys", "ON")?; // bez tego SQLite ignoruje ON DELETE CASCADE
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

pub fn find_user_by_username(conn: &Connection, username: &str) -> rusqlite::Result<Option<User>> {
    conn.query_row(
        &format!("SELECT {USER_COLS} FROM users WHERE username = ?1"),
        [username],
        User::from_row,
    )
    .optional()
}

pub fn find_user_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<User>> {
    conn.query_row(
        &format!("SELECT {USER_COLS} FROM users WHERE id = ?1"),
        [id],
        User::from_row,
    )
    .optional()
}

pub fn list_users(conn: &Connection) -> rusqlite::Result<Vec<User>> {
    let mut stmt = conn.prepare(&format!("SELECT {USER_COLS} FROM users ORDER BY id"))?;
    stmt.query_map([], User::from_row)?.collect()
}

/// Tworzy konto z hasłem jednorazowym (użytkownik musi je zmienić przy pierwszym logowaniu).
pub fn insert_user(
    conn: &Connection,
    username: &str,
    full_name: &str,
    role: Role,
    password_hash: &str,
    one_time_expires_at: i64,
    builtin: bool,
) -> rusqlite::Result<i64> {
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT INTO users (username, full_name, role, password_hash, password_changed_at, \
         must_change_password, one_time_expires_at, is_builtin) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7)",
        params![username, full_name, role.as_str(), password_hash, now(), one_time_expires_at, builtin],
    )?;
    let id = tx.last_insert_rowid();
    add_history(&tx, id, password_hash)?;
    tx.commit()?;
    Ok(id)
}

/// Ustawia nowe hasło i dopisuje jego hash do historii.
/// `one_time_expires_at = Some(..)` oznacza hasło jednorazowe nadane przez administratora.
pub fn set_password(
    conn: &Connection,
    user_id: i64,
    password_hash: &str,
    must_change: bool,
    one_time_expires_at: Option<i64>,
) -> rusqlite::Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "UPDATE users SET password_hash = ?1, password_changed_at = ?2, \
         must_change_password = ?3, one_time_expires_at = ?4 WHERE id = ?5",
        params![
            password_hash,
            now(),
            must_change,
            one_time_expires_at,
            user_id
        ],
    )?;
    add_history(&tx, user_id, password_hash)?;
    tx.commit()
}

fn add_history(conn: &Connection, user_id: i64, hash: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO password_history (user_id, password_hash) VALUES (?1, ?2)",
        params![user_id, hash],
    )?;
    Ok(())
}

/// Czas blokady konta po przekroczeniu limitu błędnych logowań.
pub const LOCKOUT_SECS: i64 = 15 * 60;

/// Zlicza błędne logowanie. Po `max_attempts` błędach blokuje konto na `LOCKOUT_SECS`
/// i zeruje licznik (po wygaśnięciu blokady użytkownik ma znów pełny limit prób).
/// Zwraca `locked_until` po aktualizacji – jeśli jest w przyszłości, konto jest zablokowane.
pub fn register_failed_login(
    conn: &Connection,
    user_id: i64,
    max_attempts: u32,
    now: i64,
) -> rusqlite::Result<i64> {
    conn.execute(
        "UPDATE users SET \
           locked_until    = CASE WHEN failed_attempts + 1 >= ?2 THEN ?3 ELSE locked_until END, \
           failed_attempts = CASE WHEN failed_attempts + 1 >= ?2 THEN 0 ELSE failed_attempts + 1 END \
         WHERE id = ?1",
        params![user_id, max_attempts, now + LOCKOUT_SECS],
    )?;
    conn.query_row("SELECT locked_until FROM users WHERE id = ?1", [user_id], |r| r.get(0))
}

pub fn reset_failed_logins(conn: &Connection, user_id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?1",
        [user_id],
    )?;
    Ok(())
}

/// Hashe wszystkich dotychczasowych haseł użytkownika (z aktualnym włącznie).
pub fn password_history(conn: &Connection, user_id: i64) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT password_hash FROM password_history WHERE user_id = ?1")?;
    stmt.query_map([user_id], |r| r.get(0))?.collect()
}
