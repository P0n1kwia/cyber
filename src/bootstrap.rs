use crate::{
    db,
    models::{Role, now},
    password::{self, OTP_VALIDITY_SECS},
};
use rusqlite::Connection;

/// Tworzy stałe konto ADMIN, jeśli go nie ma, i zwraca jego hasło jednorazowe
/// (wypisujemy je w konsoli tylko ten jeden raz).
pub fn ensure_admin(conn: &Connection) -> Result<Option<String>, String> {
    if db::find_user_by_username(conn, "ADMIN")
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Ok(None);
    }
    let one_time = password::generate_one_time();
    let hash = password::hash(&one_time)?;
    db::insert_user(
        conn,
        "ADMIN",
        "Administrator systemu",
        Role::Administrator,
        &hash,
        now() + OTP_VALIDITY_SECS,
        true,
    )
    .map_err(|e| e.to_string())?;
    Ok(Some(one_time))
}

/// Tworzy 5 użytkowników testowych; zwraca (login, rola, hasło jednorazowe) dla nowo
/// utworzonych. Istniejące konta są pomijane.
pub fn seed_test_users(conn: &Connection) -> Result<Vec<(String, Role, String)>, String> {
    const USERS: [(&str, &str, Role); 5] = [
        ("redaktor1", "Jan Kowalski", Role::Redaktor),
        ("redaktor2", "Anna Nowak", Role::Redaktor),
        ("czytelnik1", "Piotr Wiśniewski", Role::Czytelnik),
        ("czytelnik2", "Maria Zielińska", Role::Czytelnik),
        ("czytelnik3", "Tomasz Mazur", Role::Czytelnik),
    ];
    let mut created = Vec::new();
    for (login, name, role) in USERS {
        if db::find_user_by_username(conn, login)
            .map_err(|e| e.to_string())?
            .is_some()
        {
            continue;
        }
        let one_time = password::generate_one_time();
        let hash = password::hash(&one_time)?;
        db::insert_user(
            conn,
            login,
            name,
            role,
            &hash,
            now() + OTP_VALIDITY_SECS,
            false,
        )
        .map_err(|e| e.to_string())?;
        created.push((login.to_string(), role, one_time));
    }
    Ok(created)
}
