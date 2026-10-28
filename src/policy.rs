use crate::settings::Settings;
const BANNED: &str = include_str!("../data/banned_passwords.txt");

pub fn validate(password: &str, username: &str, settings: &Settings) -> Vec<String> {
    let len = password.chars().count();
    let mut violations = Vec::new();

    if len < settings.min_length as usize {
        violations.push(format!(
            "Hasło musi mieć co najmniej {} znaków (podano {}).",
            settings.min_length, len
        ));
    }
    if settings.forbid_repeats && has_repeated_run(password) {
        violations.push(
            "Hasło nie może zawierać 3 lub więcej identycznych znaków z rzędu (np. aaa, 111)."
                .to_string(),
        );
    }
    if is_banned(password, username) {
        violations.push("Hasło jest zbyt popularne lub identyczne z loginem.".to_string());
    }
    violations
}


pub fn has_repeated_run(s: &str) -> bool {
    let mut prev = None;
    let mut run = 0;
    for c in s.chars() {
        if Some(c) == prev {
            run += 1;
        } else {
            prev = Some(c);
            run = 1;
        }
        if run >= 3 {
            return true;
        }
    }
    false
}

fn is_banned(password: &str, username: &str) -> bool {
    let lower = password.to_lowercase();
    lower == username.to_lowercase() || BANNED.lines().any(|line| line.trim() == lower)
}
