"""Estado compartido de la sesion de auditoria."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .core.scanner import AccessPoint, Client


@dataclass
class AppState:
    session_dir: Path

    # Autorizacion
    authorized: bool = False
    auth_timestamp: str = ""

    # Interfaz
    iface: str | None = None
    monitor_iface: str | None = None

    # Descubrimiento
    aps: dict[str, AccessPoint] = field(default_factory=dict)
    clients: dict[str, Client] = field(default_factory=dict)

    # Objetivo
    target_bssid: str | None = None
    target_channel: str | None = None

    # Resultados
    cracks: list[dict] = field(default_factory=list)
    attacks: list[str] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
