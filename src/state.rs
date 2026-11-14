use crate::{captcha::Captcha, ip_limit::IpLimiter};
use rusqlite::Connection;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone)]
pub struct AppState {
    db: Arc<Mutex<Connection>>,
    captcha: Arc<Captcha>,
    ip_limiter: Arc<IpLimiter>,
}

impl AppState {
    pub fn new(conn: Connection) -> Self {
        AppState {
            db: Arc::new(Mutex::new(conn)),
            captcha: Arc::new(Captcha::from_env()),
            ip_limiter: Arc::new(IpLimiter::default()),
        }
    }


    pub fn captcha(&self) -> &Captcha {
        &self.captcha
    }

    pub fn ip_limiter(&self) -> &IpLimiter {
        &self.ip_limiter
    }

    pub fn conn(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }
}
