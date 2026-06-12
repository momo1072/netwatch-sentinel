import requests
from pathlib import Path

for l in Path(".env").read_text().splitlines():
    if "TELEGRAM_TOKEN" in l:
        token = l.split("=", 1)[1].strip()

r = requests.get(f"https://api.telegram.org/bot{token}/getMe")
print(r.text)