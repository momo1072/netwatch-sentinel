"""
netwatch-sentinel :: core/scanner.py
--------------------------------------
Scannt das lokale Netzwerk nach aktiven Hosts.
Nutzt python-nmap und gibt strukturierte Host-Daten zurück.

Lernfeld 09 – Netzwerke und Dienste
FISI Umschulung – GFN Hamburg
"""

import nmap
import socket
import json
import logging
from datetime import datetime
from typing import List, Dict

logger = logging.getLogger("netwatch.scanner")


def get_local_ip() -> str:
    """Ermittelt die eigene lokale IP-Adresse."""
    try:
        # Verbindung zu 8.8.8.8 — nur um die eigene IP zu bestimmen (kein Traffic)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_network_range(local_ip: str, prefix: int = 24) -> str:
    """
    Berechnet das Netzwerk-CIDR aus einer lokalen IP.
    Beispiel: 192.168.2.100 -> 192.168.2.0/24
    """
    parts = local_ip.split(".")
    parts[-1] = "0"
    return f"{'.'.join(parts)}/{prefix}"


def scan_network(network: str, arguments: str = "-sn") -> List[Dict]:
    """
    Führt einen Netzwerk-Scan durch (Ping-Scan by default).

    Parameter:
        network    : CIDR-Notation, z.B. '192.168.2.0/24'
        arguments  : nmap-Argumente
                     -sn  = Ping Scan (kein Port-Scan)
                     -sV  = Service/Version Erkennung
                     -O   = OS-Erkennung (braucht root)

    Gibt eine Liste von Host-Dictionaries zurück.
    """
    nm = nmap.PortScanner()
    logger.info(f"Starte Scan: {network} | Args: {arguments}")

    try:
        nm.scan(hosts=network, arguments=arguments)
    except nmap.PortScannerError as e:
        logger.error(f"Nmap Fehler: {e}")
        return []

    hosts = []
    for host in nm.all_hosts():
        state = nm[host].state()
        if state != "up":
            continue

        # Hostname auflösen
        try:
            hostname = socket.gethostbyaddr(host)[0]
        except socket.herror:
            hostname = "unbekannt"

        # MAC-Adresse und Hersteller (nur mit root-Rechten verfügbar)
        mac = "N/A"
        vendor = "N/A"
        if "mac" in nm[host].get("addresses", {}):
            mac = nm[host]["addresses"]["mac"]
        if "vendor" in nm[host] and mac in nm[host]["vendor"]:
            vendor = nm[host]["vendor"][mac]

        host_info = {
            "ip": host,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor,
            "state": state,
            "timestamp": datetime.now().isoformat(),
        }

        hosts.append(host_info)
        logger.debug(f"Host gefunden: {host} ({hostname}) MAC: {mac}")

    logger.info(f"Scan abgeschlossen. {len(hosts)} Hosts gefunden.")
    return hosts


def print_hosts_table(hosts: List[Dict]) -> None:
    """Gibt die Hosts als formatierte Tabelle in der Konsole aus."""
    if not hosts:
        print("  Keine Hosts gefunden.")
        return

    # Header
    print(f"\n  {'IP-Adresse':<18} {'Hostname':<30} {'MAC-Adresse':<20} {'Hersteller':<25}")
    print("  " + "-" * 93)

    for h in hosts:
        print(
            f"  {h['ip']:<18} {h['hostname'][:28]:<30} {h['mac']:<20} {h['vendor'][:23]:<25}"
        )
    print()


if __name__ == "__main__":
    # Schnelltest direkt ausführbar
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    local_ip = get_local_ip()
    network = get_network_range(local_ip)

    print(f"\n[netwatch-sentinel] Eigene IP: {local_ip}")
    print(f"[netwatch-sentinel] Scanne Netzwerk: {network}\n")

    hosts = scan_network(network)
    print_hosts_table(hosts)

    # Ergebnis als JSON speichern
    with open("scan_result.json", "w") as f:
        json.dump(hosts, f, indent=2, ensure_ascii=False)
    print(f"  Ergebnis gespeichert: scan_result.json")
