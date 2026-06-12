"""
netwatch-sentinel :: alerts/notifier.py
-----------------------------------------
Sendet Telegram-Alerts bei Netzwerk-Anomalien.
Nutzt die Telegram Bot API direkt (kein extra Framework nötig).

FISI Umschulung – GFN Hamburg | LF09
"""

import os
import requests
import logging
from datetime import datetime
from typing import Dict, List
from pathlib import Path

logger = logging.getLogger("netwatch.alerts")

# .env Datei laden (Token + Chat-ID)
def load_env():
    """Lädt Variablen aus der .env Datei."""
    env_path = Path(".env")
    if not env_path.exists():
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ[key.strip()] = value.strip()

load_env()

TELEGRAM_TOKEN   = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")


# ─────────────────────────────────────────────
# Telegram API
# ─────────────────────────────────────────────

def send_telegram(message: str) -> bool:
    """
    Sendet eine Nachricht via Telegram Bot API.
    Gibt True zurück wenn erfolgreich, sonst False.
    """
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        logger.error("Telegram Token oder Chat-ID fehlt! Prüfe die .env Datei.")
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",  # Erlaubt <b>bold</b> und <code>code</code>
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            logger.info("Telegram Alert gesendet ✓")
            return True
        else:
            logger.error(f"Telegram Fehler: {response.status_code} | {response.text}")
            return False
    except requests.RequestException as e:
        logger.error(f"Netzwerk-Fehler beim Telegram-Versand: {e}")
        return False


# ─────────────────────────────────────────────
# Alert-Nachrichten formatieren
# ─────────────────────────────────────────────

def format_alert(alert: Dict) -> str:
    """Formatiert einen Alert als lesbare Telegram-Nachricht."""
    zeitstempel = datetime.now().strftime("%d.%m.%Y %H:%M:%S")

    if alert["typ"] == "neues_geraet":
        return (
            f"🔔 <b>NETWATCH SENTINEL</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"⚠️ <b>Neues Gerät im Netzwerk!</b>\n\n"
            f"🌐 IP-Adresse: <code>{alert['ip']}</code>\n"
            f"🔌 MAC-Adresse: <code>{alert['mac']}</code>\n"
            f"🕐 Zeitstempel: {zeitstempel}\n\n"
            f"<i>Ist das Gerät bekannt? Falls nicht: Netzwerk prüfen!</i>"
        )

    elif alert["typ"] == "arp_spoofing_verdacht":
        return (
            f"🚨 <b>NETWATCH SENTINEL</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🔴 <b>ARP-SPOOFING VERDACHT!</b>\n\n"
            f"🌐 IP-Adresse: <code>{alert['ip']}</code>\n"
            f"✅ Bekannte MAC: <code>{alert['mac_bekannt']}</code>\n"
            f"❌ Neue MAC: <code>{alert['mac_aktuell']}</code>\n"
            f"🕐 Zeitstempel: {zeitstempel}\n\n"
            f"<i>Möglicher Man-in-the-Middle Angriff! Sofort prüfen!</i>"
        )

    elif alert["typ"] == "neuer_port":
        return (
            f"🔔 <b>NETWATCH SENTINEL</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"⚠️ <b>Neuer offener Port!</b>\n\n"
            f"🌐 Host: <code>{alert['ip']}</code>\n"
            f"🚪 Port: <code>:{alert['port']}</code>\n"
            f"🔧 Service: <code>{alert['service']}</code>\n"
            f"🕐 Zeitstempel: {zeitstempel}"
        )

    else:
        return (
            f"ℹ️ <b>NETWATCH SENTINEL</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"{alert.get('nachricht', 'Unbekannter Alert')}\n"
            f"🕐 {zeitstempel}"
        )


def send_alerts(alerts: List[Dict]) -> None:
    """Sendet alle Alerts als Telegram-Nachrichten."""
    if not alerts:
        return

    for alert in alerts:
        nachricht = format_alert(alert)
        send_telegram(nachricht)


def send_startup_message() -> None:
    """Sendet eine Startnachricht wenn das Monitoring beginnt."""
    nachricht = (
        f"✅ <b>NETWATCH SENTINEL gestartet</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🟢 Monitoring aktiv\n"
        f"🕐 {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n\n"
        f"<i>Du wirst bei Anomalien sofort benachrichtigt.</i>"
    )
    send_telegram(nachricht)


# ─────────────────────────────────────────────
# Test
# ─────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    print("\n[netwatch-sentinel] Sende Test-Nachricht an Telegram...\n")
    send_startup_message()

    # Beispiel-Alert testen
    test_alert = {
        "typ": "neues_geraet",
        "ip": "192.168.2.99",
        "mac": "de:ad:be:ef:00:01",
        "nachricht": "Test-Alert"
    }
    send_alerts([test_alert])
    print("Fertig! Schau in Telegram. 📱")