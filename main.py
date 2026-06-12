"""
netwatch-sentinel :: main.py
------------------------------
Hauptprogramm – startet das Monitoring.
Führt Scanner, ARP-Monitor und Port-Watcher zusammen.

Verwendung:
    python main.py              # Einmaliger Scan + Check
    python main.py --learn      # Netzwerk als Baseline speichern
    python main.py --watch 60   # Dauerhaftes Monitoring (alle 60 Sek.)

FISI Umschulung – GFN Hamburg | LF09
"""

import argparse
import time
import sys
from datetime import datetime

# Logging zuerst einrichten
from logs.logger import setup_logger
logger = setup_logger("netwatch")

from core.scanner import get_local_ip, get_network_range, scan_network, print_hosts_table
from core.arp_monitor import learn_network, run_arp_check, print_alerts
from core.port_watcher import scan_ports, print_port_table


BANNER = r"""
 ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
 ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
 ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
 ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
                          S E N T I N E L
          Heimnetz-Überwachung | FISI Umschulung | GFN Hamburg
"""


def run_once() -> None:
    """Führt einen einzelnen Scan-Durchlauf aus."""
    print(BANNER)
    print(f"  Zeitstempel: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
    print("  " + "─" * 60)

    local_ip = get_local_ip()
    network = get_network_range(local_ip)

    # ── 1. Netzwerk scannen ──────────────────────────────
    print(f"\n  [1/3] Netzwerk-Scan: {network}")
    hosts = scan_network(network)
    print_hosts_table(hosts)

    # ── 2. ARP-Check ────────────────────────────────────
    print("  [2/3] ARP-Monitor")
    alerts = run_arp_check()
    print_alerts(alerts)

    # ── 3. Port-Check (nur eigener Pi) ──────────────────
    print(f"  [3/3] Port-Check auf eigenem Host: {local_ip}")
    ports = scan_ports(local_ip, ports="1-1024")
    print_port_table(local_ip, ports)

    if alerts:
        logger.warning(f"Scan-Durchlauf: {len(alerts)} Alert(s) generiert")
    else:
        logger.info("Scan-Durchlauf abgeschlossen. Keine Anomalien.")


def run_watch(interval: int) -> None:
    """Dauerhaftes Monitoring mit konfigurierbarem Intervall."""
    print(BANNER)
    print(f"  Dauerhaftes Monitoring gestartet (Intervall: {interval}s)")
    print("  Beenden mit Ctrl+C\n")

    run_count = 0
    try:
        while True:
            run_count += 1
            print(f"\n{'─' * 60}")
            print(f"  Scan #{run_count} | {datetime.now().strftime('%H:%M:%S')}")
            print(f"{'─' * 60}")

            alerts = run_arp_check()
            print_alerts(alerts)

            print(f"  Nächster Scan in {interval} Sekunden...")
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n  [!] Monitoring beendet.\n")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="netwatch-sentinel — Heimnetz-Überwachung",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  python main.py                  Einmaliger vollständiger Scan
  python main.py --learn          Aktuelles Netzwerk als Baseline speichern
  python main.py --watch 30       ARP-Monitoring alle 30 Sekunden
        """
    )

    parser.add_argument(
        "--learn",
        action="store_true",
        help="Aktuelles Netzwerk lernen (Baseline erstellen)"
    )
    parser.add_argument(
        "--watch",
        type=int,
        metavar="SEKUNDEN",
        help="Dauerhaftes Monitoring mit Intervall in Sekunden"
    )

    args = parser.parse_args()

    if args.learn:
        print(BANNER)
        print("  [netwatch-sentinel] Lerne Netzwerk-Baseline...\n")
        learn_network()
    elif args.watch:
        run_watch(args.watch)
    else:
        run_once()


if __name__ == "__main__":
    main()
