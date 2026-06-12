"""
netwatch-sentinel :: logs/logger.py
-------------------------------------
Strukturiertes Logging im JSON-Format.
Logs können später von Grafana/Loki eingelesen werden.

FISI Umschulung – GFN Hamburg | LF09
"""

import logging
import json
from datetime import datetime
from pathlib import Path


LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "netwatch.log"


class JsonFormatter(logging.Formatter):
    """
    Formatiert Log-Einträge als JSON-Objekte.
    Jede Zeile in der Log-Datei ist ein valides JSON-Objekt.
    Das erlaubt einfaches Parsen und Visualisieren (z.B. mit Grafana).
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "nachricht": record.getMessage(),
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)


def setup_logger(name: str = "netwatch", level: int = logging.INFO) -> logging.Logger:
    """
    Richtet den netwatch Logger ein.
    - Console: lesbares Format mit Farben
    - Datei: JSON-Format für Weiterverarbeitung
    """
    LOG_DIR.mkdir(exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Nicht doppelt hinzufügen bei mehrfachem Aufruf
    if logger.handlers:
        return logger

    # ── Console Handler (lesbar) ──────────────────────────
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_format = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)-20s  %(message)s",
        datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)

    # ── File Handler (JSON) ───────────────────────────────
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(JsonFormatter())
    logger.addHandler(file_handler)

    return logger


if __name__ == "__main__":
    log = setup_logger("netwatch.test", logging.DEBUG)
    log.debug("Debug-Nachricht (wird in Datei gespeichert)")
    log.info("Info: System gestartet")
    log.warning("Warnung: Unbekanntes Gerät erkannt")
    log.critical("Kritisch: ARP-Spoofing Verdacht!")
    print(f"\nLog gespeichert in: {LOG_FILE}")
