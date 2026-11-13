use std::time::Duration;


pub const TRAP_USERNAME: &str = "admin.backup";


pub fn trap_triggered(attempted_login: &str) {
    eprintln!("CANARY: próba logowania na konto-pułapkę „{attempted_login}”");
    let Some(url) = std::env::var("CANARY_URL").ok().filter(|u| !u.is_empty()) else {
        eprintln!("CANARY: brak zmiennej CANARY_URL – alert nie zostanie wysłany");
        return;
    };
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("AuthLab-trap-account")
            .build();
        let result = match client {
            Ok(c) => c.get(url).send().await.map(|r| r.status()),
            Err(e) => Err(e),
        };
        match result {
            Ok(status) => eprintln!("CANARY: alert wysłany (HTTP {status})"),
            Err(e) => eprintln!("CANARY: nie udało się wysłać alertu: {e}"),
        }
    });
}
