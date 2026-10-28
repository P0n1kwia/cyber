use authlab::{AppState, bootstrap, db};

const DB_FILE: &str = "authlab.sqlite";
const ADDR: &str = "127.0.0.1:3000";

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("błąd: {msg}");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {

    let command = std::env::args().nth(1).unwrap_or_else(|| "serve".into());
    if command != "serve" && command != "seed" {
        fail("nieznane polecenie – użyj `serve` albo `seed`");
    }

    let conn = db::open(DB_FILE).unwrap_or_else(|e| fail(format!("baza {DB_FILE}: {e}")));


    if let Some(one_time) = bootstrap::ensure_admin(&conn).unwrap_or_else(|e| fail(e)) {
        println!("Utworzono konto ADMIN, hasło jednorazowe: {one_time} (ważne 24 h)");
    }

    if command == "seed" {
        let created = bootstrap::seed_test_users(&conn).unwrap_or_else(|e| fail(e));
        if created.is_empty() {
            println!("Użytkownicy testowi już istnieją.");
        }
        for (login, role, one_time) in created {
            println!(
                "{login:<11} {:<9} hasło jednorazowe: {one_time}",
                role.as_str()
            );
        }
        return;
    }

    let app = authlab::build_router(AppState::new(conn));
    let listener = tokio::net::TcpListener::bind(ADDR)
        .await
        .unwrap_or_else(|e| fail(format!("nie można nasłuchiwać na {ADDR}: {e}")));
    println!("Serwer działa: http://{ADDR}");
    axum::serve(listener, app).await.unwrap_or_else(|e| fail(e));
}
