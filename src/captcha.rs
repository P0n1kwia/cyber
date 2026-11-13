use crate::error::{AppError, AppResult};
use serde::Deserialize;
use std::time::Duration;

const VERIFY_URL: &str = "https://www.google.com/recaptcha/api/siteverify";

const TEST_SITE_KEY: &str = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI";
const TEST_SECRET: &str = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe";

pub struct Captcha {
    site_key: String,
    secret: String,
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct VerifyResponse {
    success: bool,
}

impl Captcha {
    pub fn from_env() -> Self {
        let var = |name: &str, default: &str| {
            std::env::var(name)
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| default.to_string())
        };
        if std::env::var("RECAPTCHA_SECRET").is_err() {
            println!("reCAPTCHA: używam publicznych kluczy testowych Google (ustaw RECAPTCHA_SITE_KEY i RECAPTCHA_SECRET)");
        }
        Captcha {
            site_key: var("RECAPTCHA_SITE_KEY", TEST_SITE_KEY),
            secret: var("RECAPTCHA_SECRET", TEST_SECRET),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("klient HTTP"),
        }
    }

    /// Klucz publiczny, który frontend podaje widżetowi reCAPTCHA.
    pub fn site_key(&self) -> &str {
        &self.site_key
    }

    /// Weryfikacja tokenu u Google (token jest jednorazowy i krótko ważny).
    /// Brak tokenu, błąd sieci lub odmowa Google = odrzucenie.
    async fn verify(&self, token: &str) -> bool {
        if token.trim().is_empty() {
            return false;
        }
        let params = [("secret", self.secret.as_str()), ("response", token)];
        let resp = match self.client.post(VERIFY_URL).form(&params).send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("reCAPTCHA: błąd połączenia z Google: {e}");
                return false;
            }
        };
        match resp.json::<VerifyResponse>().await {
            Ok(v) => v.success,
            Err(e) => {
                eprintln!("reCAPTCHA: nieczytelna odpowiedź Google: {e}");
                false
            }
        }
    }

    /// Zwraca błąd 400 `captcha_failed`, jeśli token jest pusty albo nie przeszedł weryfikacji.
    pub async fn require(&self, token: &str) -> AppResult<()> {
        if self.verify(token).await {
            Ok(())
        } else {
            Err(AppError::bad_request(
                "captcha_failed",
                "Weryfikacja CAPTCHA nie powiodła się. Spróbuj ponownie.",
            ))
        }
    }
}
