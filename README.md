# Piotr Ponikwia Wariant 1

## cargo run --release -- seed
tworzy konto ADMIN i 5 użytkowników testowych, wypisuje ich hasła jednorazowe
## cargo run --release           
serwer na http://127.0.0.1:3000

#Powershell Canarytoken
$env:CANARY_URL="http://canarytokens.com/traffic/sgnbd8h8eo6l2tb2pt2u13utc/index.html"; cargo run --release