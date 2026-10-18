"""Pruebas del flujo automatico con hardware simulado.

No requieren root, adaptador Wi-Fi ni la suite aircrack-ng: se parchean las
fronteras del sistema (procesos, interfaz, IA) para validar la logica del
orquestador.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wifi_audit.core import ai
from wifi_audit.core import orchestrator as O
from wifi_audit.core.runner import CommandResult

CSV = """\
BSSID, First time, Last time, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2026-01-01 00:00:00, 2026-01-01 00:00:10, 6, 54, WPA2, CCMP, PSK, -40, 100, 0, 0.0.0.0, 7, MiRed

Station MAC, First time, Last time, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2026-01-01 00:00:00, 2026-01-01 00:00:10, -50, 10, AA:BB:CC:DD:EE:FF,
"""


class FakeProc:
    """Sustituto de ManagedProcess que simula handshake y clave encontrada."""

    def __init__(self, argv, log_file=None):
        self.argv = [str(a) for a in argv]
        self.log_file = Path(log_file) if log_file else None
        self._lines: list[str] = []

    def start(self) -> "FakeProc":
        joined = " ".join(self.argv)
        if "--write" in self.argv or "airodump-ng" in joined:
            if self.log_file:
                self.log_file.write_text(
                    "WPA handshake: AA:BB:CC:DD:EE:FF\n", encoding="utf-8")
        if "aircrack-ng" in self.argv[0]:
            self._lines = ["Opening cap", "KEY FOUND! [ 12345678 ]", "done"]
        return self

    def stop(self) -> None:
        pass

    def poll(self):
        return 0

    def running(self) -> bool:
        return False

    def wait(self, timeout=None):
        return 0

    def lines(self):
        return iter(self._lines)


@pytest.fixture
def session(tmp_path: Path) -> Path:
    (tmp_path / "auto-scan-01.csv").write_text(CSV, encoding="utf-8")
    (tmp_path / "auto-capture-01.cap").write_bytes(b"\x00")
    (tmp_path / "rockyou.txt").write_text("123456\n12345678\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def patched(monkeypatch):
    """Parchea las fronteras del sistema para el orquestador."""
    monkeypatch.setattr(O, "ManagedProcess", FakeProc)
    monkeypatch.setattr(O, "run_blocking",
                        lambda argv, timeout=20: CommandResult(list(argv), 0, ""))
    monkeypatch.setattr(O.interface, "is_available", lambda n: True)
    monkeypatch.setattr(O.interface, "list_wireless_interfaces", lambda: ["wlan0"])
    monkeypatch.setattr(O.interface, "is_monitor", lambda i: False)
    monkeypatch.setattr(O.interface, "check_kill", lambda: "")
    monkeypatch.setattr(O.interface, "start_monitor", lambda i: "wlan0mon")
    monkeypatch.setattr(O.interface, "stop_monitor", lambda i: "")
    monkeypatch.setattr(O.interface, "interface_mac", lambda i: "00:11:22:33:44:55")


def _run(session: Path, use_ai: bool) -> tuple[dict, list[str]]:
    logs: list[str] = []
    auditor = O.AutoAuditor(
        session, iface="wlan0", wordlist=str(session / "rockyou.txt"),
        scan_seconds=1, capture_seconds=2, use_ai=use_ai,
        on_log=logs.append, on_event=lambda _m: None,
    )
    return auditor.run(), logs


def test_plan_determinista_recupera_clave(session, patched, monkeypatch):
    monkeypatch.setattr(ai, "available", lambda: False)
    result, logs = _run(session, use_ai=False)
    assert result["plan"]["approach"] == "handshake"
    assert result["plan"]["source"] == "determinista"
    assert result["crack"] == "clave_encontrada"
    assert result["key"] == "12345678"
    assert len(logs) > 5


def test_plan_con_ia(session, patched, monkeypatch):
    monkeypatch.setattr(ai, "available", lambda: True)
    monkeypatch.setattr(ai, "plan_target", lambda fp, cl, fb: {
        "approach": "handshake", "rationale": "IA", "steps": ["capturar"]})
    monkeypatch.setattr(ai, "interpret_results", lambda s: "Analisis IA.")
    result, _ = _run(session, use_ai=True)
    assert result["plan"]["source"] == "ia"
    assert result["ai_analysis"] == "Analisis IA."


def test_restaura_monitor(session, patched, monkeypatch):
    calls = {"stop": 0}
    monkeypatch.setattr(ai, "available", lambda: False)
    monkeypatch.setattr(O.interface, "stop_monitor",
                        lambda i: calls.__setitem__("stop", calls["stop"] + 1))
    _run(session, use_ai=False)
    assert calls["stop"] == 1
