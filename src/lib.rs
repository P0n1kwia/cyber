

pub mod bootstrap;
pub mod canary;
pub mod captcha;
pub mod db;
pub mod error;
pub mod handlers;
pub mod ip_limit;
pub mod models;
pub mod password;
pub mod policy;
pub mod session;
pub mod settings;
pub mod state;
pub mod totp;

pub use state::AppState;

pub fn build_router(state: AppState) -> axum::Router {
    handlers::router(state)
}
