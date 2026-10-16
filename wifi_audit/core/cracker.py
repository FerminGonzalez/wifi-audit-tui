"""Construccion de comandos y parseo de resultados de aircrack-ng."""

from __future__ import annotations

import re
from pathlib import Path

# Ej: "KEY FOUND! [ 12345678 ]"
_KEY_RE = re.compile(r"KEY FOUND!\s*\[\s*(.*?)\s*\]")
# Ej: "0 handshake(s) found" o "1 handshake(s) found"
_HANDSHAKE_RE = re.compile(r"(\d+)\s+handshake")
# Ej: "PMKID found"
_PMKID_RE = re.compile(r"PMKID.*found", re.IGNORECASE)


def build_aircrack_argv(
    capfile: Path,
    wordlist: Path | None = None,
    bssid: str | None = None,
    essid: str | None = None,
    cpus: int | None = None,
) -> list[str]:
    """Construye la invocacion de aircrack-ng.

    aircrack-ng 1.6+ detecta PMKID automaticamente; no se necesita flag extra.
    """
    argv = ["aircrack-ng"]
    if wordlist:
        argv += ["-w", str(wordlist)]
    if bssid:
        argv += ["-b", bssid]
    if essid:
        argv += ["-e", essid]
    if cpus:
        argv += ["-p", str(cpus)]
    argv.append(str(capfile))
    return argv


def parse_key_found(line: str) -> str | None:
    match = _KEY_RE.search(line)
    return match.group(1) if match else None


def parse_handshakes(text: str) -> int | None:
    match = _HANDSHAKE_RE.search(text)
    return int(match.group(1)) if match else None


def has_pmkid(text: str) -> bool:
    return bool(_PMKID_RE.search(text))


def is_dictionary_exhausted(line: str) -> bool:
    lowered = line.lower()
    return "passphrase not in dictionary" in lowered or (
        "not found" in lowered and "key" in lowered
    )
