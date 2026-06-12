"""
netwatch-sentinel :: core/port_watcher.py
-------------------------------------------
Überwacht offene Ports auf Hosts im Netzwerk.
Erkennt neue oder unerwartet geöffnete Ports.

Konzept:
  Ports sind wie Türen in ein System.
  - Bekannte / erwartete Ports sind OK (z.B. :80 HTTP, :22 SSH)
  - Unbekannte offene Ports können auf einen Angriff oder
    eine Fehlkonfiguration hinweisen

FISI Umschulung – GFN Hamburg | LF09
"""

import nmap
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger("netwatch.ports")

# Snapshot der letzten bekannten Port-Zustände
SNAPSHOT_PATH = Path("config/port_snapshot.json")

# Bekannte / harmlose Ports (Whitelist) mit Erklärung
COMMON_PORTS = {
    22:   "SSH – Fernzugriff (sollte gesichert sein!)",
    53:   "DNS – Namensauflösung",
    80:   "HTTP – Webserver (unverschlüsselt)",
    443:  "HTTPS – Webserver (verschlüsselt)",
    139:  "NetBIOS – Windows Dateifreigabe",
    445:  "SMB – Windows Dateifreigabe",
    3000: "Grafana Dashboard",
    3306: "MySQL Datenbank",
    5432: "PostgreSQL Datenbank",
    8080: "HTTP Alternative / Proxy",
    9090: "Prometheus Metrics",
    9100: "Node Exporter (Prometheus)",
}


def scan_ports(ip: str, ports: str = "1-1024") -> Dict:
    """
    Scannt einen einzelnen Host auf offene Ports.

    Parameter:
        ip    : Ziel-IP-Adresse
        ports : Port-Range, z.B. '1-1024' oder '22,80,443'

    Gibt ein Dict mit offenen Ports zurück:
    { 22: {"state": "open", "service": "ssh"}, ... }
    """
    nm = nmap.PortScanner()
    logger.info(f"Scanne Ports auf {ip}: {ports}")

    try:
        nm.scan(hosts=ip, arguments=f"-p {ports} --open")
    except nmap.PortScannerError as e:
        logger.error(f"Nmap Fehler bei {ip}: {e}")
        return {}

    open_ports = {}
    if ip not in nm.all_hosts():
        return {}

    for proto in nm[ip].all_protocols():
        for port in nm[ip][proto].keys():
            port_info = nm[ip][proto][port]
            if port_info["state"] == "open":
                open_ports[port] = {
                    "protokoll": proto,
                    "state": port_info["state"],
                    "service": port_info.get("name", "unbekannt"),
                    "version": port_info.get("version", ""),
                    "bekannt": COMMON_PORTS.get(port, None),
                }

    logger.info(f"Offene Ports auf {ip}: {list(open_ports.keys())}")
    return open_ports


def save_port_snapshot(snapshot: Dict) -> None:
    """Speichert den aktuellen Port-Status als Baseline."""
    SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(SNAPSHOT_PATH, "w") as f:
        json.dump(snapshot, f, indent=2)
    logger.info(f"Port-Snapshot gespeichert: {SNAPSHOT_PATH}")


def load_port_snapshot() -> Dict:
    """Lädt den gespeicherten Port-Snapshot."""
    if not SNAPSHOT_PATH.exists():
        return {}
    with open(SNAPSHOT_PATH, "r") as f:
        return json.load(f)


def compare_ports(
    ip: str,
    current: Dict,
    baseline: Dict
) -> List[Dict]:
    """
    Vergleicht aktuelle Ports mit dem gespeicherten Baseline-Snapshot.
    Erkennt:
      - Neu geöffnete Ports (potenzielle Bedrohung)
      - Geschlossene Ports (Service ausgefallen?)
    """
    alerts = []
    baseline_ports = set(map(int, baseline.get(ip, {}).keys()))
    current_ports = set(current.keys())

    # Neu geöffnete Ports
    new_ports = current_ports - baseline_ports
    for port in new_ports:
        info = current[port]
        alert = {
            "typ": "neuer_port",
            "schwere": "WARNUNG" if port in COMMON_PORTS else "KRITISCH",
            "ip": ip,
            "port": port,
            "service": info["service"],
            "nachricht": (
                f"Neuer offener Port auf {ip}: :{port} "
                f"({info['service']}) "
                f"{'– ' + COMMON_PORTS[port] if port in COMMON_PORTS else '– UNBEKANNTER SERVICE!'}"
            ),
            "timestamp": datetime.now().isoformat(),
        }
        alerts.append(alert)
        logger.warning(f"[NEUER PORT] {ip}:{port} ({info['service']})")

    # Geschlossene Ports (Service weg)
    closed_ports = baseline_ports - current_ports
    for port in closed_ports:
        alert = {
            "typ": "port_geschlossen",
            "schwere": "INFO",
            "ip": ip,
            "port": port,
            "nachricht": f"Port auf {ip} nicht mehr offen: :{port}",
            "timestamp": datetime.now().isoformat(),
        }
        alerts.append(alert)
        logger.info(f"[PORT GESCHLOSSEN] {ip}:{port}")

    return alerts


def print_port_table(ip: str, ports: Dict) -> None:
    """Gibt offene Ports als Tabelle aus."""
    print(f"\n  Offene Ports auf {ip}:")
    if not ports:
        print("    Keine offenen Ports gefunden.\n")
        return

    print(f"  {'Port':<8} {'Protokoll':<12} {'Service':<15} {'Bekannt als'}")
    print("  " + "-" * 70)
    for port, info in sorted(ports.items()):
        bekannt = info.get("bekannt") or "⚠ Unbekannt"
        print(f"  {port:<8} {info['protokoll']:<12} {info['service']:<15} {bekannt}")
    print()


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    # Beispiel: direkt einen Host scannen
    ziel = sys.argv[1] if len(sys.argv) > 1 else "192.168.2.1"
    print(f"\n[netwatch-sentinel] Scanne Ports auf {ziel}...")

    ports = scan_ports(ziel, ports="1-1024")
    print_port_table(ziel, ports)
