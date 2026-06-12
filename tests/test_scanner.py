"""
netwatch-sentinel :: tests/test_scanner.py
--------------------------------------------
Unit Tests für den Scanner und ARP-Monitor.
Ausführen mit: python -m pytest tests/

FISI Umschulung – GFN Hamburg | LF09
"""

import unittest
from unittest.mock import patch, MagicMock

# Module importieren (aus dem übergeordneten Verzeichnis)
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scanner import get_local_ip, get_network_range
from core.arp_monitor import check_for_anomalies


class TestNetworkHelpers(unittest.TestCase):
    """Tests für Netzwerk-Hilfsfunktionen."""

    def test_get_network_range_standard(self):
        """CIDR-Berechnung für typische Heimnetz-IP."""
        result = get_network_range("192.168.2.100", prefix=24)
        self.assertEqual(result, "192.168.2.0/24")

    def test_get_network_range_different_subnet(self):
        """CIDR-Berechnung für andere Subnetz-Klasse."""
        result = get_network_range("10.0.1.50", prefix=24)
        self.assertEqual(result, "10.0.1.0/24")

    def test_get_network_range_prefix_16(self):
        """CIDR mit /16 Prefix."""
        result = get_network_range("172.16.5.100", prefix=16)
        self.assertEqual(result, "172.16.5.0/16")


class TestArpMonitor(unittest.TestCase):
    """Tests für die ARP-Anomalie-Erkennung."""

    def test_no_anomalies_when_known(self):
        """Keine Alerts wenn alle Geräte bekannt sind."""
        current = {
            "192.168.2.1": "aa:bb:cc:dd:ee:ff",
            "192.168.2.100": "11:22:33:44:55:66",
        }
        known = current.copy()  # Identische Baseline

        alerts = check_for_anomalies(current, known)
        self.assertEqual(len(alerts), 0)

    def test_new_device_detected(self):
        """Neues Gerät wird als 'neues_geraet' Alert erkannt."""
        known = {"192.168.2.1": "aa:bb:cc:dd:ee:ff"}
        current = {
            "192.168.2.1": "aa:bb:cc:dd:ee:ff",
            "192.168.2.55": "ff:ee:dd:cc:bb:aa",  # Neu!
        }

        alerts = check_for_anomalies(current, known)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["typ"], "neues_geraet")
        self.assertEqual(alerts[0]["ip"], "192.168.2.55")

    def test_arp_spoofing_detected(self):
        """MAC-Wechsel auf bekannter IP wird als Spoofing erkannt."""
        known = {"192.168.2.1": "aa:bb:cc:dd:ee:ff"}
        current = {"192.168.2.1": "00:11:22:33:44:55"}  # Andere MAC!

        alerts = check_for_anomalies(current, known)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["typ"], "arp_spoofing_verdacht")
        self.assertEqual(alerts[0]["schwere"], "KRITISCH")
        self.assertEqual(alerts[0]["mac_bekannt"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(alerts[0]["mac_aktuell"], "00:11:22:33:44:55")

    def test_multiple_anomalies(self):
        """Mehrere Anomalien gleichzeitig werden alle erkannt."""
        known = {
            "192.168.2.1": "aa:bb:cc:dd:ee:ff",
            "192.168.2.10": "11:22:33:44:55:66",
        }
        current = {
            "192.168.2.1": "00:00:00:00:00:01",  # Spoofing
            "192.168.2.10": "11:22:33:44:55:66",   # OK
            "192.168.2.99": "ff:ff:ff:ff:ff:ff",   # Neu
        }

        alerts = check_for_anomalies(current, known)
        self.assertEqual(len(alerts), 2)

        typen = {a["typ"] for a in alerts}
        self.assertIn("arp_spoofing_verdacht", typen)
        self.assertIn("neues_geraet", typen)


if __name__ == "__main__":
    unittest.main(verbosity=2)
