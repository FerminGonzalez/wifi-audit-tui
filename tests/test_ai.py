"""Pruebas de la capa de IA (validacion y extraccion de JSON)."""

from __future__ import annotations

import pytest

from wifi_audit.core import ai


def test_extract_json_fenced():
    data = ai._extract_json('```json\n{"approach": "pmkid"}\n```')
    assert data["approach"] == "pmkid"


def test_extract_json_sin_json():
    with pytest.raises(ai.AIError):
        ai._extract_json("no hay nada aqui")


def test_plan_target_valido(monkeypatch):
    monkeypatch.setattr(ai, "_chat", lambda *a, **k: (
        '{"approach": "pmkid", "rationale": "r", "steps": ["capturar"]}'))
    out = ai.plan_target({"bssid": "AA"}, [], {"approach": "handshake"})
    assert out["approach"] == "pmkid"
    assert out["steps"] == ["capturar"]


def test_plan_target_rechaza_enfoque_no_permitido(monkeypatch):
    monkeypatch.setattr(ai, "_chat",
                        lambda *a, **k: '{"approach": "evil-trick"}')
    with pytest.raises(ai.AIError):
        ai.plan_target({}, [], {})


def test_describe_backend_desactivado(monkeypatch):
    monkeypatch.setattr(ai, "AI_MODE", "off")
    assert "desactivada" in ai.describe_backend()
    assert ai.resolve_backend() is None
