#!/usr/bin/env python3
"""Symulacja bota atakującego logowanie w AuthLab (tylko biblioteka standardowa).

Uruchomienie przy działającym serwerze:
    python tools/bot_test.py [--url http://127.0.0.1:3000] [--user redaktor1]

Bot rozmawia z serwerem samym HTTP-em: nie widzi widżetu CAPTCHA, więc tam, gdzie ma dojść dalej
niż CAPTCHA, wysyła zmyślony token. Przy publicznych kluczach testowych Google każdy niepusty
token przechodzi weryfikację (widać wtedy pozostałe zabezpieczenia); przy własnych kluczach
reCAPTCHA zatrzymuje bota już na pierwszym żądaniu.

Licznik adresu IP jest w pamięci serwera, a konto --user po teście jest zablokowane na 15 minut,
więc przed ponownym uruchomieniem zrestartuj serwer i użyj innego konta (--user).
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

FAKE_TOKEN = "bot-fake-token"
SPRAY_PASSWORD = "Summer2026!"
MAX_TRIES = 30
TRAP_LOGIN = "admin.backup"  # login konta-pułapki (Canarytoken)

# kod błędu z serwera -> zabezpieczenie, które zatrzymało żądanie
STOPPERS = {
    "bot_detected": "honeypot",
    "captcha_failed": "CAPTCHA",
    "account_locked": "blokada konta",
    "ip_limited": "limit prób z adresu IP",
}


def login(base, username, password, token=None, website=None):
    """Jedno żądanie POST /api/login; zwraca (status HTTP, kod błędu lub 'ok')."""
    body = {"username": username, "password": password}
    if token is not None:
        body["captcha_token"] = token
    if website is not None:
        body["website"] = website
    req = urllib.request.Request(
        base + "/api/login",
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, "ok"
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read()).get("error", "?")
        except ValueError:
            return e.code, "?"
    except urllib.error.URLError as e:
        sys.exit(f"Nie można połączyć się z {base}: {e.reason}. Uruchom serwer (cargo run --release).")


def stopped(code):
    return "TAK" if code in STOPPERS else "NIE"


def run_until_stopped(base, attempts):
    """Wysyła kolejne próby, aż serwer przestanie odpowiadać 401 invalid_credentials."""
    for n, (user, password) in enumerate(attempts, 1):
        status, code = login(base, user, password, FAKE_TOKEN)
        if code != "invalid_credentials":
            before = f"{n - 1}× 401, potem " if n > 1 else ""
            return f"{before}{status} {code} (próba {n})", stopped(code)
    return f"{len(attempts)}× 401 invalid_credentials, nic nie zatrzymało bota", "NIE"


def main():
    parser = argparse.ArgumentParser(description="Symulacja bota atakującego logowanie w AuthLab")
    parser.add_argument("--url", default="http://127.0.0.1:3000")
    parser.add_argument("--user", default="redaktor1", help="konto atakowane brute force'em")
    args = parser.parse_args()
    base = args.url.rstrip("/")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    rows = []

    # 1. Bot wypełnia wszystkie pola formularza, także ukryte.
    status, code = login(base, args.user, "x", FAKE_TOKEN, website="http://spam.example")
    rows.append(("Wypełnione ukryte pole formularza", "Honeypot", f"{status} {code}", stopped(code)))

    # 2. Bot wysyła żądanie bez tokenu CAPTCHA.
    status, code = login(base, args.user, "x")
    rows.append(("Logowanie bez tokenu CAPTCHA", "CAPTCHA", f"{status} {code}", stopped(code)))

    # 3. Próba wejścia na konto-pułapkę; odpowiedź wygląda zwyczajnie, alarm idzie poza serwer.
    #    (Przed brute force i sprayingiem, żeby odpowiedź nie zasłonił limit adresu IP.)
    status, code = login(base, TRAP_LOGIN, "admin123", FAKE_TOKEN)
    rows.append((f"Logowanie na konto-pułapkę ({TRAP_LOGIN})", "Canarytoken (alert e-mail)",
                 f"{status} {code}", "RĘCZNIE"))

    # 4. Brute force: kolejne hasła na jedno konto (musi być przed spraying, patrz limit IP).
    attempts = [(args.user, f"haslo{i}") for i in range(1, MAX_TRIES + 1)]
    text, result = run_until_stopped(base, attempts)
    rows.append((f"Brute force na jedno konto ({args.user})", "Blokada konta po N błędach", text, result))

    # 5. Password spraying: jedno hasło na wielu kontach (pojedyncze konta się nie blokują).
    names = ["redaktor2", "czytelnik1", "czytelnik2", "czytelnik3", "ADMIN", "admin", "root", "test",
             "guest", "editor", "reader", "info", "support", "demo", "service"]
    names += [f"user{i}" for i in range(1, MAX_TRIES)]
    attempts = [(u, SPRAY_PASSWORD) for u in names if u.lower() != args.user.lower()][:MAX_TRIES]
    text, result = run_until_stopped(base, attempts)
    rows.append(("Password spraying (jedno hasło, wiele kont)", "Limit prób z adresu IP", text, result))

    header = ("Nr", "Scenariusz", "Zabezpieczenie", "Odpowiedź serwera", "Zatrzymany?")
    table = [header] + [(str(i), *row) for i, row in enumerate(rows, 1)]
    widths = [max(len(r[c]) for r in table) for c in range(len(header))]
    line = lambda r: "| " + " | ".join(cell.ljust(widths[c]) for c, cell in enumerate(r)) + " |"
    print(f"\nCel: {base}\n")
    print(line(header))
    print("|" + "|".join("-" * (w + 2) for w in widths) + "|")
    for r in table[1:]:
        print(line(r))
    print("\nRĘCZNIE = tego nie widać w odpowiedzi serwera (celowo wygląda jak zwykła porażka logowania); "
          "sprawdź e-mail od Canarytokens i wpis 'CANARY:' w logu serwera.")
    sys.exit(1 if any(r[3] == "NIE" for r in rows) else 0)


if __name__ == "__main__":
    main()
