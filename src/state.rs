use crate::captcha::Captcha;
use rusqlite::Connection;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone)]
pub struct AppState {
    db: Arc<Mutex<Connection>>,
    captcha: Arc<Captcha>,
}

impl AppState {
    pub fn new(conn: Connection) -> Self {
        AppState {
            db: Arc::new(Mutex::new(conn)),
            captcha: Arc::new(Captcha::from_env()),
        }
    }


    pub fn captcha(&self) -> &Captcha {
        &self.captcha
    }

    pub fn conn(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }
}
