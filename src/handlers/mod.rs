mod account;
mod admin;
mod articles;
mod auth;

use crate::state::AppState;
use axum::{
    Router,
    http::header,
    response::{Html, IntoResponse},
    routing::{delete, get, patch, post},
};

async fn index() -> Html<&'static str> {
    Html(include_str!("../../static/index.html"))
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../static/app.js"),
    )
}

async fn style_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../static/style.css"),
    )
}

pub fn router(state: AppState) -> Router {
    Router::new()
        // frontend (pliki statyczne wbudowane w program)
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/style.css", get(style_css))
        // logowanie, sesja, hasło
        .route("/api/login", post(auth::login))
        .route("/api/login/totp", post(auth::login_totp))
        .route("/api/logout", post(auth::logout))
        .route("/api/me", get(auth::me))
        .route("/api/change-password", post(auth::change_password))
        // własne TOTP
        .route("/api/totp/setup", post(account::totp_setup))
        .route("/api/totp/enable", post(account::totp_enable))
        .route("/api/totp/disable", post(account::totp_disable))
        // panel administratora
        .route(
            "/api/admin/users",
            get(admin::list_users).post(admin::create_user),
        )
        .route(
            "/api/admin/users/{id}",
            patch(admin::update_user).delete(admin::delete_user),
        )
        .route(
            "/api/admin/users/{id}/reset-password",
            post(admin::reset_password),
        )
        .route(
            "/api/admin/settings",
            get(admin::get_settings).put(admin::put_settings),
        )
        // artykuły – zasób do pokazania ról Redaktor / Czytelnik
        .route("/api/articles", get(articles::list).post(articles::create))
        .route("/api/articles/{id}", delete(articles::remove))
        .with_state(state)
}
