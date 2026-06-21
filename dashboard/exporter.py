"""
netwatch-sentinel :: dashboard/exporter.py
Prometheus Exporter - stellt Netwatch-Metriken bereit
Port: 8888
"""

import time
import subprocess
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

def get_arp_table():
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    pattern = re.compile(r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-f:]{17})", re.IGNORECASE)
    devices = {}
    for match in pattern.finditer(result.stdout):
        devices[match.group(1)] = match.group(2).lower()
    return devices

def generate_metrics():
    devices = get_arp_table()
    count = len(devices)
    ts = int(datetime.now().timestamp() * 1000)

    lines = []
    lines.append("# HELP netwatch_devices_total Anzahl aktiver Geraete im Netzwerk")
    lines.append("# TYPE netwatch_devices_total gauge")
    lines.append(f"netwatch_devices_total {count}")
    lines.append("")
    lines.append("# HELP netwatch_scan_timestamp Letzter Scan Unix-Timestamp")
    lines.append("# TYPE netwatch_scan_timestamp gauge")
    lines.append(f"netwatch_scan_timestamp {ts}")
    lines.append("")
    lines.append("# HELP netwatch_device_up Geraet aktiv (1=ja)")
    lines.append("# TYPE netwatch_device_up gauge")
    for ip, mac in devices.items():
        safe_ip = ip.replace(".", "_")
        safe_mac = mac.replace(":", "")
        lines.append(f'netwatch_device_up{{ip="{ip}",mac="{mac}"}} 1')

    return "\n".join(lines) + "\n"

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            metrics = generate_metrics()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            self.wfile.write(metrics.encode())
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Netwatch Exporter - /metrics")

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    port = 8888
    print(f"[netwatch-exporter] Starte auf Port {port}...")
    print(f"[netwatch-exporter] Metriken: http://192.168.2.186:{port}/metrics")
    server = HTTPServer(("0.0.0.0", port), MetricsHandler)
    server.serve_forever()
