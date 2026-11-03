use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;


#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// Minimalna długość hasła (wariant 1: domyślnie 15).
    pub min_length: u32,
    /// Reguła dodatkowa wariantu 1: zakaz 3 lub więcej identycznych znaków z rzędu.
    pub forbid_repeats: bool,
    /// Ważność hasła w dniach; 0 = hasło nie wygasa (zalecenie NIST).
    pub password_max_age_days: u32,
    /// Czas bezczynności, po którym sesja wygasa (w minutach).
    pub session_idle_minutes: u32,
    /// Liczba błędnych logowań, po której konto jest blokowane na 15 minut.
    #[serde(default = "default_max_login_attempts")]
    pub max_login_attempts: u32,
}

fn default_max_login_attempts() -> u32 {
    5
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            min_length: 15,
            forbid_repeats: false,
            password_max_age_days: 0,
            session_idle_minutes: 15,
            max_login_attempts: default_max_login_attempts(),
        }
    }
}

impl Settings {
    /// Lista błędów walidacji (pusta = ustawienia poprawne).
    pub fn validate(&self) -> Vec<&'static str> {
        let mut errs = vec![];
        if !(8..=64).contains(&self.min_length) {
            errs.push("Minimalna długość hasła: 8–64.");
        }
        if self.password_max_age_days > 3650 {
            errs.push("Ważność hasła: najwyżej 3650 dni (0 = bez wygasania).");
        }
        if !(1..=1440).contains(&self.session_idle_minutes) {
            errs.push("Czas bezczynności sesji: 1–1440 minut.");
        }
        if !(1..=20).contains(&self.max_login_attempts) {
            errs.push("Liczba prób logowania do blokady: 1–20.");
        }
        errs
    }
}

pub fn load(conn: &Connection) -> rusqlite::Result<Settings> {
    let mut stmt = conn.prepare("SELECT key, value FROM settings")?;
    let map: HashMap<String, String> = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<_>>()?;

    let d = Settings::default();
    let num =
        |key: &str, default: u32| map.get(key).and_then(|v| v.parse().ok()).unwrap_or(default);
    Ok(Settings {
        min_length: num("min_length", d.min_length),
        forbid_repeats: map
            .get("forbid_repeats")
            .map(|v| v == "1")
            .unwrap_or(d.forbid_repeats),
        password_max_age_days: num("password_max_age_days", d.password_max_age_days),
        session_idle_minutes: num("session_idle_minutes", d.session_idle_minutes),
        max_login_attempts: num("max_login_attempts", d.max_login_attempts),
    })
}

pub fn save(conn: &Connection, s: &Settings) -> rusqlite::Result<()> {
    let pairs = [
        ("min_length", s.min_length.to_string()),
        (
            "forbid_repeats",
            if s.forbid_repeats { "1" } else { "0" }.to_string(),
        ),
        ("password_max_age_days", s.password_max_age_days.to_string()),
        ("session_idle_minutes", s.session_idle_minutes.to_string()),
        ("max_login_attempts", s.max_login_attempts.to_string()),
    ];
    for (key, value) in pairs {
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
    }
    Ok(())
}
