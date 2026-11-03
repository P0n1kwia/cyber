use rusqlite::Row;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};


pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}



#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Administrator,
    Redaktor,
    Czytelnik,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Permission {
    UsersManage,
    SettingsManage,
    ArticlesRead,
    ArticlesCreate,
    ArticlesDeleteOwn,
    ArticlesDeleteAny,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::UsersManage => "users.manage",
            Permission::SettingsManage => "settings.manage",
            Permission::ArticlesRead => "articles.read",
            Permission::ArticlesCreate => "articles.create",
            Permission::ArticlesDeleteOwn => "articles.delete_own",
            Permission::ArticlesDeleteAny => "articles.delete_any",
        }
    }
}

impl Role {
    const ALL: [Role; 3] = [Role::Administrator, Role::Redaktor, Role::Czytelnik];

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Administrator => "Administrator",
            Role::Redaktor => "Redaktor",
            Role::Czytelnik => "Czytelnik",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.as_str() == s)
    }


    pub fn permissions(self) -> &'static [Permission] {
        use Permission::*;
        match self {
            Role::Administrator => &[UsersManage, SettingsManage, ArticlesRead, ArticlesDeleteAny],
            Role::Redaktor => &[ArticlesRead, ArticlesCreate, ArticlesDeleteOwn],
            Role::Czytelnik => &[ArticlesRead],
        }
    }

    pub fn has(self, p: Permission) -> bool {
        self.permissions().contains(&p)
    }
}

// --- użytkownik ----------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub full_name: String,
    pub role: Role,
    pub password_hash: String,
    pub password_changed_at: i64,
    pub must_change_password: bool,
    pub one_time_expires_at: Option<i64>,
    pub is_blocked: bool,
    pub is_builtin: bool,
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub totp_last_step: i64,
    pub failed_attempts: i64,
    pub locked_until: i64,
}

pub const USER_COLS: &str = "id, username, full_name, role, password_hash, password_changed_at, \
    must_change_password, one_time_expires_at, is_blocked, is_builtin, totp_secret, \
    totp_enabled, totp_last_step, failed_attempts, locked_until";

impl User {
    pub fn from_row(r: &Row<'_>) -> rusqlite::Result<User> {
        let role: String = r.get(3)?;
        Ok(User {
            id: r.get(0)?,
            username: r.get(1)?,
            full_name: r.get(2)?,
            role: Role::parse(&role).ok_or_else(|| {
                rusqlite::Error::InvalidColumnType(3, "role".into(), rusqlite::types::Type::Text)
            })?,
            password_hash: r.get(4)?,
            password_changed_at: r.get(5)?,
            must_change_password: r.get(6)?,
            one_time_expires_at: r.get(7)?,
            is_blocked: r.get(8)?,
            is_builtin: r.get(9)?,
            totp_secret: r.get(10)?,
            totp_enabled: r.get(11)?,
            totp_last_step: r.get(12)?,
            failed_attempts: r.get(13)?,
            locked_until: r.get(14)?,
        })
    }


    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "username": self.username,
            "full_name": self.full_name,
            "role": self.role.as_str(),
            "blocked": self.is_blocked,
            "builtin": self.is_builtin,
            "one_time_expires_at": self.one_time_expires_at,
            "totp_enabled": self.totp_enabled,
        })
    }
}
