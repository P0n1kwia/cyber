use crate::{
    error::{AppError, AppResult},
    models::{Permission, now},
    session::CurrentUser,
    state::AppState,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
pub struct NewArticle {
    title: String,
    body: String,
}

pub async fn list(State(st): State<AppState>, cu: CurrentUser) -> AppResult<Json<Value>> {
    cu.require(Permission::ArticlesRead)?;
    let conn = st.conn();
    let mut stmt = conn.prepare(
        "SELECT a.id, a.title, a.body, u.username, a.created_at \
         FROM articles a LEFT JOIN users u ON u.id = a.author_id ORDER BY a.id DESC",
    )?;
    let articles = stmt
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "title": r.get::<_, String>(1)?,
                "body": r.get::<_, String>(2)?,
                "author": r.get::<_, Option<String>>(3)?,
                "created_at": r.get::<_, i64>(4)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(json!({ "articles": articles })))
}

pub async fn create(
    State(st): State<AppState>,
    cu: CurrentUser,
    Json(req): Json<NewArticle>,
) -> AppResult<(StatusCode, Json<Value>)> {
    cu.require(Permission::ArticlesCreate)?;
    let (title, body) = (req.title.trim(), req.body.trim());
    if title.is_empty() || title.chars().count() > 200 || body.is_empty() {
        return Err(AppError::bad_request(
            "invalid_article",
            "Podaj tytuł (do 200 znaków) i treść.",
        ));
    }
    let conn = st.conn();
    conn.execute(
        "INSERT INTO articles (title, body, author_id, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![title, body, cu.user().id, now()],
    )?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": conn.last_insert_rowid() })),
    ))
}

pub async fn remove(
    State(st): State<AppState>,
    cu: CurrentUser,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    let conn = st.conn();
    let author: Option<i64> = conn
        .query_row("SELECT author_id FROM articles WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .optional()?
        .ok_or_else(AppError::not_found)?;

    let role = cu.user().role;
    let own = author == Some(cu.user().id);
    if !(role.has(Permission::ArticlesDeleteAny)
        || (own && role.has(Permission::ArticlesDeleteOwn)))
    {
        return Err(AppError::forbidden(
            "forbidden",
            "Brak uprawnień do usunięcia tego artykułu.",
        ));
    }
    conn.execute("DELETE FROM articles WHERE id = ?1", [id])?;
    Ok(Json(json!({ "ok": true })))
}
