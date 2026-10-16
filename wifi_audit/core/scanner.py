"""Parser del CSV que genera airodump-ng con --write.

El formato del CSV tiene dos secciones separadas por lineas en blanco:

  * Access Points : BSSID, First time, Last time, channel, Speed, Privacy,
    Cipher, Authentication, Power, #beacons, #IV, LAN IP, ID-length, ESSID
  * Clients       : Station MAC, First time, Last time, Power, #packets,
    BSSID, Probed ESSIDs

Las ESSID pueden contener comas (airodump no las escapa), por lo que el
ultimo campo se reconstruye uniendo el resto de la linea.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AccessPoint:
    bssid: str
    channel: str = ""
    privacy: str = ""
    cipher: str = ""
    auth: str = ""
    power: str = ""
    beacons: str = "0"
    data: str = "0"
    essid: str = ""
    clients: list[str] = field(default_factory=list)

    @property
    def encryption(self) -> str:
        p = (self.privacy or "").strip().upper()
        if not p or p == "OPN":
            return "ABIERTA"
        if "WPA3" in p:
            return "WPA3"
        if "WPA2" in p or p == "WPA2":
            return "WPA2"
        if p.startswith("WPA"):
            return "WPA"
        if p.startswith("WEP"):
            return "WEP"
        return p

    @property
    def display_essid(self) -> str:
        return self.essid or "<oculta>"


@dataclass
class Client:
    mac: str
    power: str = ""
    packets: str = "0"
    bssid: str = ""
    probed: str = ""


def parse_airodump_csv(path: Path) -> tuple[dict[str, AccessPoint], dict[str, Client]]:
    """Devuelve (access_points, clients) indexados por BSSID/MAC."""
    aps: dict[str, AccessPoint] = {}
    clients: dict[str, Client] = {}

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, OSError):
        return aps, clients

    section = "ap"
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("BSSID") and "First time" in stripped:
            section = "ap"
            continue
        if stripped.startswith("Station MAC"):
            section = "client"
            continue

        fields = [f.strip() for f in line.split(",")]

        if section == "ap":
            if len(fields) < 14:
                continue
            bssid = fields[0]
            if not bssid or bssid.upper() == "BSSID":
                continue
            aps[bssid] = AccessPoint(
                bssid=bssid,
                channel=fields[3],
                privacy=fields[5],
                cipher=fields[6],
                auth=fields[7],
                power=fields[8],
                beacons=fields[9] or "0",
                data=fields[10] or "0",
                essid=",".join(fields[13:]).strip(),
            )
        else:
            if len(fields) < 6:
                continue
            mac = fields[0]
            if not mac or mac.upper() == "STATION MAC":
                continue
            client = Client(
                mac=mac,
                power=fields[3],
                packets=fields[4] or "0",
                bssid=fields[5],
                probed=",".join(fields[6:]).strip(),
            )
            clients[mac] = client
            ap = aps.get(client.bssid)
            if ap and mac not in ap.clients:
                ap.clients.append(mac)

    return aps, clients


def latest_csv(prefix: Path) -> Path | None:
    """Devuelve el CSV mas reciente generado con ``-w <prefix>``."""
    candidates = sorted(prefix.parent.glob(prefix.name + "-*.csv"))
    if not candidates:
        return None
    return candidates[-1]


def list_capture_files(session_dir: Path) -> list[Path]:
    """Ficheros de captura (.cap/.pcap) de la sesion, mas recientes primero."""
    files: list[Path] = []
    for pattern in ("*.cap", "*.pcap"):
        files.extend(session_dir.glob(pattern))
    return sorted(set(files), key=lambda p: p.stat().st_mtime, reverse=True)
