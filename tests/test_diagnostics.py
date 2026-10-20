"""Pruebas del modo diagnostico (funciones puras, sin herramientas del sistema)."""

from __future__ import annotations

from wifi_audit.diagnostics import classify_usb_id, check_deps, check_python


def test_check_python_ok():
    msg, ok = check_python()
    assert isinstance(msg, str)
    assert ok is True  # el proyecto requiere Python >= 3.10


def test_check_deps_devuelve_estructura():
    msg, ok = check_deps()
    assert isinstance(msg, str)
    assert isinstance(ok, bool)


def test_classify_usb_id_compatible():
    name, ok = classify_usb_id("0cf3:9271")
    assert ok is True
    assert "AR9271" in name


def test_classify_usb_id_limitado_mt7921():
    name, ok = classify_usb_id("0e8d:7961")
    assert ok is False
    assert "MT7921" in name


def test_classify_usb_id_desconocido_vendor_wifi():
    name, ok = classify_usb_id("0bda:9999")
    assert ok is None
    assert name != ""


def test_classify_usb_id_no_wifi():
    name, ok = classify_usb_id("1d6b:0002")
    assert ok is None
    assert name == ""
