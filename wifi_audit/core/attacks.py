"""Construccion de comandos de aireplay-ng y airbase-ng.

ATENCION: estas operaciones son ACTIVAS y solo deben usarse sobre redes
propias o con autorizacion escrita.
"""

from __future__ import annotations

from pathlib import Path


def deauth_argv(
    iface: str,
    bssid: str,
    client: str | None = None,
    count: int = 5,
) -> list[str]:
    """Desautenticacion dirigida a un AP (y opcionalmente a un cliente)."""
    argv = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
    if client:
        argv += ["-c", client]
    argv.append(iface)
    return argv


def fakeauth_argv(iface: str, bssid: str, essid: str | None = None) -> list[str]:
    """Autenticacion simulada (preambulo clasico de ataques WEP)."""
    argv = ["aireplay-ng", "--fakeauth", "0", "-a", bssid]
    if essid:
        argv += ["-e", essid]
    argv.append(iface)
    return argv


def arpreplay_argv(iface: str, bssid: str, source_mac: str) -> list[str]:
    """Reinyeccion ARP (genera IVs, util en auditorias WEP)."""
    return [
        "aireplay-ng",
        "--arpreplay",
        "-b",
        bssid,
        "-h",
        source_mac,
        iface,
    ]


def airbase_argv(
    iface: str,
    essid: str,
    channel: int | None = None,
) -> list[str]:
    """Crea un AP falso (open) con airbase-ng."""
    argv = ["airbase-ng", "-e", essid, "-P"]
    if channel:
        argv += ["-c", str(channel)]
    argv.append(iface)
    return argv


def capture_argv(
    iface: str,
    prefix: Path,
    bssid: str | None = None,
    channel: str | None = None,
) -> list[str]:
    """airodump-ng dirigido a un objetivo, generando CSV y pcap."""
    argv = ["airodump-ng", "--write", str(prefix), "--output-format", "csv,pcap",
            "--write-interval", "1"]
    if channel:
        argv += ["-c", str(channel)]
    if bssid:
        argv += ["--bssid", bssid]
    argv.append(iface)
    return argv


def scan_argv(
    iface: str,
    prefix: Path,
    channel: str | None = None,
    bssid: str | None = None,
) -> list[str]:
    """airodump-ng en modo barrido (solo CSV, sin pcap)."""
    argv = ["airodump-ng", "--write", str(prefix), "--output-format", "csv",
            "--write-interval", "1"]
    if channel:
        argv += ["-c", str(channel)]
    if bssid:
        argv += ["--bssid", bssid]
    argv.append(iface)
    return argv
