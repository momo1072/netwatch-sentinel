"""
netwatch-sentinel :: core/arp_monitor.py
------------------------------------------
Überwacht die ARP-Tabelle des Systems.
Erkennt neue / unbekannte MAC-Adressen und mögliche ARP-Spoofing-Versuche.

Konzept: ARP (Address Resolution Protocol)
  - Jedes Gerät im LAN hat eine IP und eine MAC-Adresse
  - ARP mappt IP → MAC
  - ARP-Spoofing: Angreifer behauptet, eine fremde IP zu besitzen
    → gefährlich für Man-in-the-Middle Angriffe

FISI Umschulung – GFN Hamburg | LF09
"""

import subprocess
import re
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("netwatch.arp")

# Pfad zur bekannten Geräte-Datenbank (Whitelist)
KNOWN_DEVICES_PATH = Path("config/known_devices.json")


# ─────────────────────────────────────────────
# ARP-Tabelle lesen
# ─────────────────────────────────────────────

def get_arp_table() -> Dict[str, str]:
    """
    Liest die aktuelle ARP-Tabelle des Betriebssystems.
    Gibt ein Dictionary zurück: { "192.168.2.1": "aa:bb:cc:dd:ee:ff", ... }

    Funktioniert auf Linux und macOS.
    """
    arp_map = {}

    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        output = result.stdout
    except FileNotFoundError:
        logger.error("'arp' Befehl nicht gefunden. Läuft das System auf Linux/macOS?")
        return {}

    # Regex: IP in Klammern und MAC-Adresse
    pattern = re.compile(r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-f:]{17})", re.IGNORECASE)

    for match in pattern.finditer(output):
        ip = match.group(1)
        mac = match.group(2).lower()
        arp_map[ip] = mac

    logger.debug(f"ARP-Tabelle eingelesen: {len(arp_map)} Einträge")
    return arp_map


# ─────────────────────────────────────────────
# Bekannte Geräte (Whitelist)
# ─────────────────────────────────────────────

def load_known_devices() -> Dict[str, str]:
    """
    Lädt bekannte Geräte aus der JSON-Konfiguration.
    Format: { "192.168.2.1": "aa:bb:cc:dd:ee:ff" }
    """
    if not KNOWN_DEVICES_PATH.exists():
        logger.warning(f"Bekannte Geräte-Datei nicht gefunden: {KNOWN_DEVICES_PATH}")
        logger.info("Tipp: Führe 'learn_network()' aus um das Netzwerk zu lernen.")
        return {}

    with open(KNOWN_DEVICES_PATH, "r") as f:
        devices = json.load(f)

    logger.info(f"Bekannte Geräte geladen: {len(devices)} Einträge")
    return devices


def save_known_devices(devices: Dict[str, str]) -> None:
    """Speichert die bekannten Geräte in die JSON-Datei."""
    KNOWN_DEVICES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(KNOWN_DEVICES_PATH, "w") as f:
        json.dump(devices, f, indent=2)
    logger.info(f"Bekannte Geräte gespeichert: {KNOWN_DEVICES_PATH}")


def learn_network() -> None:
    """
    'Lernt' das aktuelle Netzwerk: speichert alle aktuellen ARP-Einträge
    als bekannte / vertrauenswürdige Geräte.
    Sollte einmalig beim ersten Start ausgeführt werden.
    """
    arp_table = get_arp_table()
    if not arp_table:
        logger.warning("Leere ARP-Tabelle — erst nach einem Netzwerk-Scan sinnvoll.")
        return

    save_known_devices(arp_table)
    print(f"\n  ✓ Netzwerk gelernt: {len(arp_table)} Geräte als vertrauenswürdig gespeichert.")
    for ip, mac in arp_table.items():
        print(f"    {ip:<20} → {mac}")


# ─────────────────────────────────────────────
# Anomalie-Erkennung
# ─────────────────────────────────────────────

def check_for_anomalies(
    current: Dict[str, str],
    known: Dict[str, str]
) -> List[Dict]:
    """
    Vergleicht aktuelle ARP-Tabelle mit bekannten Geräten.
    Erkennt:
      1. Neue Geräte (IP noch nie gesehen)
      2. MAC-Wechsel (selbe IP, andere MAC → mögliches ARP-Spoofing!)
    
    Gibt eine Liste von Alert-Dictionaries zurück.
    """
    alerts = []

    for ip, mac in current.items():
        if ip not in known:
            # Neues Gerät im Netzwerk
            alert = {
                "typ": "neues_geraet",
                "schwere": "INFO",
                "ip": ip,
                "mac": mac,
                "nachricht": f"Neues Gerät im Netzwerk: {ip} ({mac})",
                "timestamp": datetime.now().isoformat(),
            }
            alerts.append(alert)
            logger.warning(f"[NEUES GERÄT] {ip} | MAC: {mac}")

        elif known[ip] != mac:
            # MAC hat sich geändert → mögliches ARP-Spoofing!
            alert = {
                "typ": "arp_spoofing_verdacht",
                "schwere": "KRITISCH",
                "ip": ip,
                "mac_bekannt": known[ip],
                "mac_aktuell": mac,
                "nachricht": (
                    f"ARP-Spoofing Verdacht! {ip} hatte MAC {known[ip]}, "
                    f"jetzt: {mac}"
                ),
                "timestamp": datetime.now().isoformat(),
            }
            alerts.append(alert)
            logger.critical(f"[ARP-SPOOFING VERDACHT] {ip} | Alt: {known[ip]} | Neu: {mac}")

    return alerts


# ─────────────────────────────────────────────
# Haupt-Monitoring Funktion
# ─────────────────────────────────────────────

def run_arp_check() -> List[Dict]:
    """
    Führt einen vollständigen ARP-Check durch:
    1. ARP-Tabelle lesen
    2. Mit bekannten Geräten vergleichen
    3. Alerts zurückgeben
    """
    current_arp = get_arp_table()
    known_devices = load_known_devices()

    if not known_devices:
        print("\n  [!] Keine bekannten Geräte vorhanden.")
        print("      Führe erst 'learn_network()' aus.\n")
        return []

    alerts = check_for_anomalies(current_arp, known_devices)
    return alerts


def print_alerts(alerts: List[Dict]) -> None:
    """Gibt Alerts formatiert in der Konsole aus."""
    if not alerts:
        print("\n  ✓ Keine Anomalien erkannt. Alles normal.\n")
        return

    print(f"\n  ⚠ {len(alerts)} Anomalie(n) erkannt:\n")
    for a in alerts:
        farbe = "\033[91m" if a["schwere"] == "KRITISCH" else "\033[93m"
        reset = "\033[0m"
        print(f"  {farbe}[{a['schwere']}]{reset} {a['nachricht']}")
        print(f"           Zeitstempel: {a['timestamp']}\n")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    if len(sys.argv) > 1 and sys.argv[1] == "learn":
        print("\n[netwatch-sentinel] Lerne Netzwerk...")
        learn_network()
    else:
        print("\n[netwatch-sentinel] ARP-Monitor startet...\n")
        alerts = run_arp_check()
        print_alerts(alerts)
