"""Pruebas del informe (incluida la seccion de analisis IA)."""

from __future__ import annotations

from wifi_audit.core.report import render_markdown
from wifi_audit.core.scanner import AccessPoint


def _ap(**kw) -> AccessPoint:
    base = dict(bssid="AA:BB:CC:DD:EE:FF", channel="6", essid="MiRed",
                privacy="WPA2", auth="PSK", power="-40")
    base.update(kw)
    return AccessPoint(**base)


def test_informe_sin_ia():
    md = render_markdown({"session_dir": "/tmp/x", "authorized": "si"},
                         {"AA:BB:CC:DD:EE:FF": _ap()}, {}, [], [], [])
    assert "Informe de auditoria" in md
    assert "Analisis asistido por IA" not in md


def test_informe_con_ia():
    md = render_markdown({"session_dir": "/tmp/x", "authorized": "si"},
                         {"AA:BB:CC:DD:EE:FF": _ap()}, {}, [], [], [],
                         ai_analysis="## resumen\nTodo correcto.")
    assert "Analisis asistido por IA" in md
    assert "Todo correcto." in md
