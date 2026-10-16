"""Configuracion global, rutas de sesion y utilidades de entorno."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

APP_NAME = "WiFi Audit TUI"
VERSION = "1.0.0"

# Directorio raiz de sesiones. Configurable por variable de entorno.
SESSION_ROOT = Path(
    os.environ.get("WIFI_AUDIT_SESSIONS", str(Path.home() / "wifi-audit-sessions"))
)

# Nombres de las herramientas de la suite que usamos.
TOOL_NAMES = [
    "airmon-ng",
    "airodump-ng",
    "aireplay-ng",
    "aircrack-ng",
    "airbase-ng",
]


def new_session_dir() -> Path:
    """Crea y devuelve un directorio de sesion con marca de tiempo."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = SESSION_ROOT / f"session-{ts}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def is_root() -> bool:
    """True si el proceso corre como root (necesario para muchas operaciones)."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")
