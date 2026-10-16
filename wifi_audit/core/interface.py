"""Enumeracion de interfaces y gestion del modo monitor con airmon-ng."""

from __future__ import annotations

import re
from pathlib import Path

from .runner import CommandError, is_available, run_blocking

_SYS_NET = Path("/sys/class/net")


def list_net_interfaces() -> list[str]:
    if _SYS_NET.exists():
        return sorted(p.name for p in _SYS_NET.iterdir())
    return []


def list_wireless_interfaces() -> list[str]:
    """Interfaces que son inalambricas. Prefiere /sys, cae a ``iw``."""
    ifaces: list[str] = []
    for name in list_net_interfaces():
        if (_SYS_NET / name / "wireless").exists():
            ifaces.append(name)
    if ifaces:
        return ifaces

    if is_available("iw"):
        try:
            res = run_blocking(["iw", "dev"], timeout=5)
        except (CommandError, Exception):
            return []
        return re.findall(r"Interface\s+(\S+)", res.output)
    return []


def interface_mac(iface: str) -> str | None:
    path = _SYS_NET / iface / "address"
    if path.exists():
        try:
            return path.read_text().strip()
        except OSError:
            return None
    return None


def is_monitor(iface: str) -> bool:
    if not is_available("iw"):
        return iface.endswith("mon")
    try:
        res = run_blocking(["iw", "dev", iface, "info"], timeout=5)
    except Exception:
        return False
    return "type monitor" in res.output


def check_kill() -> str:
    """Mata procesos que interfieren con airmon-ng. Devuelve la salida."""
    res = run_blocking(["airmon-ng", "check", "kill"], timeout=30)
    return res.output


def start_monitor(iface: str) -> str | None:
    """Activa modo monitor y devuelve el nombre de la interfaz monitor."""
    before = set(list_net_interfaces())
    res = run_blocking(["airmon-ng", "start", iface], timeout=60)
    after = set(list_net_interfaces())
    new = after - before

    # 1) interfaz nueva terminada en 'mon'
    for cand in sorted(new):
        if cand.endswith("mon"):
            return cand
    # 2) cualquier interfaz nueva en modo monitor
    for cand in sorted(new):
        if is_monitor(cand):
            return cand
    # 3) la salida de airmon-ng suele indicar el nombre
    match = re.search(r"\[[^\]]*\](\S+mon)\b", res.output)
    if match:
        return match.group(1)
    match = re.search(r"on\s+\[[^\]]*\](\S+mon)\b", res.output)
    if match:
        return match.group(1)
    # 4) el mismo nombre cambio a monitor
    if is_monitor(iface):
        return iface
    return None


def stop_monitor(iface: str) -> str:
    res = run_blocking(["airmon-ng", "stop", iface], timeout=30)
    return res.output
