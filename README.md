# 🛡️ netwatch-sentinel

> **Intelligentes Heimnetz-Überwachungssystem** – gebaut auf dem Raspberry Pi 400  
> Erkennt unbekannte Geräte, überwacht ARP-Tabellen, analysiert Ports und visualisiert alles in Grafana.

---

## Was ist netwatch-sentinel?

`netwatch-sentinel` ist ein modulares Python-Tool zur Sicherheitsüberwachung von Heimnetzwerken. Es wurde im Rahmen der **FISI-Umschulung (Fachinformatiker Systemintegration)** an der GFN Hamburg entwickelt und läuft auf einem Raspberry Pi 400 als Homelab-Server.

Das Projekt verbindet Themen aus **LF09 (Netzwerke und Dienste)** mit praktischer IT-Security und zeigt, wie man ein echtes Monitoring-System von Grund auf baut — ohne fertige Security-Plattformen.

---

## Features

| Phase | Modul | Funktion |
|---|---|---|
| 1 | `core/scanner.py` | Netzwerk-Scan via nmap — welche Geräte sind online? |
| 1 | `core/arp_monitor.py` | ARP-Tabelle überwachen — neue MACs und Spoofing-Verdacht |
| 1 | `core/port_watcher.py` | Port-Monitoring — neue / unerwartet offene Ports erkennen |
| 1 | `logs/logger.py` | Strukturiertes JSON-Logging (Grafana-ready) |
| 2 | `alerts/notifier.py` | Telegram Alerts bei Anomalien auf iPhone |
| 3 | `dashboard/exporter.py` | Prometheus Exporter — Metriken für Grafana |

---

## Architektur

```
netwatch-sentinel/
├── core/
│   ├── scanner.py        # Netzwerk-Scan (nmap)
│   ├── arp_monitor.py    # ARP-Spoofing Erkennung
│   └── port_watcher.py   # Port-Monitoring
├── alerts/
│   └── notifier.py       # Telegram Alerts
├── dashboard/
│   └── exporter.py       # Prometheus Metrics Exporter (:8888)
├── logs/
│   ├── logger.py         # JSON-Logger
│   └── netwatch.log      # (wird automatisch erstellt)
├── config/
│   ├── known_devices.json  # Whitelist bekannter Geräte
│   └── port_snapshot.json  # Baseline offener Ports
├── tests/
│   └── test_scanner.py   # Unit Tests
├── main.py               # Einstiegspunkt
└── requirements.txt
```

---

## Infrastruktur

```
Raspberry Pi 400 (Hamburg)
├── netwatch-sentinel       ← dieses Projekt
├── Pi-hole                 ← DNS-Blocker
├── Docker
│   ├── Prometheus :9090    ← Metriken sammeln
│   ├── Grafana :3000       ← Dashboard visualisieren
│   └── Node Exporter :9100 ← Pi-Hardware Metriken
└── Tailscale VPN           ← Fernzugriff von überall
```

---

## Schnellstart

### 1. Voraussetzungen

```bash
sudo apt install nmap -y
pip install -r requirements.txt
```

### 2. Netzwerk lernen (einmalig)

```bash
sudo python3 main.py --learn
```

### 3. Einmaliger Scan

```bash
sudo python3 main.py
```

### 4. Dauerhaftes Monitoring

```bash
sudo python3 main.py --watch 60
```

### 5. Prometheus Exporter starten

```bash
python3 dashboard/exporter.py
# Metriken: http://192.168.2.186:8888/metrics
```

---

## Telegram Alerts

Bei Anomalien (neues Gerät, ARP-Spoofing, neuer Port) wird automatisch eine Nachricht an Telegram gesendet.

`.env` Datei erstellen:

```
TELEGRAM_TOKEN=dein_token
TELEGRAM_CHAT_ID=deine_chat_id
```

---

## Grafana Dashboard

Das Netwatch Sentinel Dashboard zeigt:
- Anzahl aktiver Geräte im Netzwerk (live)
- Zeitverlauf der Gerätezahl
- Prometheus Metriken: `netwatch_devices_total`, `netwatch_device_up`

Prometheus Konfiguration (`prometheus.yml`):

```yaml
scrape_configs:
  - job_name: 'netwatch'
    static_configs:
      - targets: ['192.168.2.186:8888']
```

---

## systemd Service

Der Exporter startet automatisch beim Pi-Boot:

```bash
sudo systemctl enable netwatch-exporter
sudo systemctl start netwatch-exporter
sudo systemctl status netwatch-exporter
```

---

## Fernzugriff via Tailscale

Mit Tailscale VPN ist der Pi von überall erreichbar:

```bash
ssh homeles82@100.101.248.114
```

Grafana im Browser:
```
http://100.101.248.114:3000
```

---

## IT-Security Konzepte in diesem Projekt

| Konzept | Umsetzung |
|---|---|
| **CIA-Triade** | Vertraulichkeit durch Port-Monitoring, Integrität durch ARP-Check |
| **ARP-Spoofing** | `arp_monitor.py` erkennt MAC-Wechsel auf bekannten IPs |
| **BSI IT-Grundschutz** | Logging und Monitoring entspricht Baustein NET.1 |
| **Incident Detection** | Anomalie-Alerts mit Schweregrad-Klassifizierung |
| **Zero Trust** | Tailscale VPN für sicheren Fernzugriff |
| **Least Privilege** | Root nur wo nötig (nmap), normaler User für Logs/Alerts |

---

## Lerntagebuch

**Phase 1 gelernt:**
- Python `subprocess` zum Lesen von Systemkommandos
- `python-nmap` als Wrapper für nmap-Scans
- Regex für das Parsen der ARP-Tabelle
- Strukturiertes JSON-Logging mit Python `logging`-Modul
- Modularer Projektaufbau mit sinnvoller Ordnerstruktur

**Phase 2 gelernt:**
- Telegram Bot API
- HTTP Requests mit Python `requests`-Bibliothek
- Umgebungsvariablen und `.env` Dateien
- Alert-System mit Schweregrad-Klassifizierung

**Phase 3 gelernt:**
- Prometheus Metriken Format
- HTTP Server in Python (`BaseHTTPRequestHandler`)
- Grafana Dashboard erstellen und konfigurieren
- systemd Services erstellen und verwalten
- Tailscale VPN einrichten

---

## Hardware

Läuft auf einem **Raspberry Pi 400** (Homelab Hamburg)
- OS: Raspberry Pi OS (Debian Bookworm)
- RAM: 4GB
- Services: Pi-hole, Docker, Grafana, Prometheus, Tailscale

---

## Roadmap

- [x] Phase 1 — Netzwerk-Scanner, ARP-Monitor, Port-Watcher
- [x] Phase 2 — Telegram Alerts
- [x] Phase 3 — Prometheus Exporter + Grafana Dashboard
- [x] systemd Service für automatischen Start
- [x] Tailscale VPN für Fernzugriff
- [ ] Phase 4 — CVE-Check gegen Schwachstellen-Datenbank
- [ ] Phase 4 — Honeypot-Erkennung
- [ ] Phase 4 — BSI IT-Grundschutz Auditbericht Generator

---

*Entwickelt von Momo · FISI Umschulung · GFN Hamburg · 2026*
