# 🛡️ netwatch-sentinel

> **Intelligentes Heimnetz-Überwachungssystem** – gebaut auf dem Raspberry Pi 400  
> Erkennt unbekannte Geräte, überwacht ARP-Tabellen und analysiert offene Ports.

---

## Was ist netwatch-sentinel?

`netwatch-sentinel` ist ein modulares Python-Tool zur Sicherheitsüberwachung von Heimnetzwerken. Es wurde im Rahmen der **FISI-Umschulung (Fachinformatiker Systemintegration)** an der GFN Hamburg entwickelt und läuft auf einem Raspberry Pi 400 als Homelab-Server.

Das Projekt verbindet Themen aus **LF09 (Netzwerke und Dienste)** mit praktischer IT-Security und zeigt, wie man ein echtes Monitoring-System von Grund auf baut — ohne fertige Security-Plattformen.

---

## Features (Phase 1)

| Modul | Funktion |
|---|---|
| `core/scanner.py` | Netzwerk-Scan via `nmap` — welche Geräte sind online? |
| `core/arp_monitor.py` | ARP-Tabelle überwachen — neue MACs und Spoofing-Verdacht |
| `core/port_watcher.py` | Port-Monitoring — neue / unerwartet offene Ports erkennen |
| `logs/logger.py` | Strukturiertes JSON-Logging (Grafana-ready) |

---

## Architektur

```
netwatch-sentinel/
├── core/
│   ├── scanner.py        # Netzwerk-Scan (nmap)
│   ├── arp_monitor.py    # ARP-Spoofing Erkennung
│   └── port_watcher.py   # Port-Monitoring
├── alerts/               # (Phase 2) Telegram / E-Mail Alerts
├── dashboard/            # (Phase 3) Prometheus Exporter + Grafana JSONs
├── logs/
│   ├── logger.py         # JSON-Logger
│   └── netwatch.log      # (wird automatisch erstellt)
├── config/
│   ├── known_devices.json  # Whitelist bekannter Geräte
│   └── port_snapshot.json  # Baseline offener Ports
├── tests/                # Unit Tests
├── main.py               # Einstiegspunkt
└── requirements.txt
```

---

## Schnellstart

### 1. Voraussetzungen

```bash
# nmap installieren (Linux/macOS)
sudo apt install nmap        # Debian/Ubuntu/Raspberry Pi OS
brew install nmap            # macOS

# Python-Abhängigkeiten
pip install -r requirements.txt
```

### 2. Netzwerk lernen (einmalig)

Beim ersten Start speicherst du das aktuelle Netzwerk als **Baseline** (vertrauenswürdige Geräte):

```bash
sudo python main.py --learn
```

> Warum `sudo`? ARP-Scans und OS-Erkennung brauchen erhöhte Rechte.

### 3. Einmaliger Scan

```bash
sudo python main.py
```

Beispiel-Output:
```
  [1/3] Netzwerk-Scan: 192.168.2.0/24

  IP-Adresse         Hostname                       MAC-Adresse          Hersteller
  ─────────────────────────────────────────────────────────────────────────────────
  192.168.2.1        router.local                   aa:bb:cc:dd:ee:ff    AVM GmbH
  192.168.2.186      raspberrypi.local              11:22:33:44:55:66    Raspberry Pi

  [2/3] ARP-Monitor
  ✓ Keine Anomalien erkannt. Alles normal.

  [3/3] Port-Check auf eigenem Host: 192.168.2.186
  Port     Protokoll    Service         Bekannt als
  ─────────────────────────────────────────────────
  22       tcp          ssh             SSH – Fernzugriff
  3000     tcp          ppp             Grafana Dashboard
  9090     tcp          zeus-admin      Prometheus Metrics
```

### 4. Dauerhaftes Monitoring

```bash
sudo python main.py --watch 60    # Prüft alle 60 Sekunden
```

---

## Geplante Features (Roadmap)

### Phase 2 — Alerts
- [ ] Telegram Bot Benachrichtigungen bei Anomalien
- [ ] E-Mail Alerts (SMTP)
- [ ] Konfigurierbare Alert-Regeln in `alerts/rules.yaml`

### Phase 3 — Dashboard
- [ ] Prometheus Exporter (`/metrics` Endpoint)
- [ ] Grafana Dashboard (Geräteanzahl, neue MACs, Port-Änderungen)
- [ ] Docker Compose für einfaches Deployment

### Phase 4 — Advanced Security
- [ ] CVE-Check gegen bekannte Schwachstellen-Datenbank
- [ ] Honeypot-Erkennung (wer scannt mich?)
- [ ] BSI IT-Grundschutz Auditbericht Generator

---

## IT-Security Konzepte in diesem Projekt

Dieses Projekt verbindet Theorie aus der FISI-Ausbildung mit praktischer Umsetzung:

| Konzept | Umsetzung im Code |
|---|---|
| **CIA-Triade** | Vertraulichkeit durch Port-Monitoring, Integrität durch ARP-Check |
| **ARP-Spoofing** | `arp_monitor.py` erkennt MAC-Wechsel auf bekannten IPs |
| **BSI IT-Grundschutz** | Logging und Monitoring entspricht Baustein NET.1 |
| **Incident Detection** | Anomalie-Alerts mit Schweregrad-Klassifizierung |
| **Least Privilege** | Root nur wo nötig (nmap), normaler User für Logs/Alerts |

---

## Lerntagebuch

> Dokumentation des Lernfortschritts — entstanden während der Umschulung

**Phase 1 gelernt:**
- Python `subprocess`-Modul zum Lesen von Systemkommandos
- `python-nmap` als Wrapper für nmap-Scans
- Regex für das Parsen der ARP-Tabelle
- Strukturiertes JSON-Logging mit Python's `logging`-Modul
- Modularer Projektaufbau mit sinnvoller Ordnerstruktur

---

## Hardware

Läuft auf einem **Raspberry Pi 400** (Homelab)
- OS: Raspberry Pi OS (Debian Bookworm)
- IP: `192.168.2.186`
- Services: Pi-hole, Docker, Grafana, Prometheus

---

## Lizenz

MIT License — freie Nutzung für Bildungszwecke.

---

*Entwickelt von Momo · FISI Umschulung · GFN Hamburg · 2026*
