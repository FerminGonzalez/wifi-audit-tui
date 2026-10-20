"""Modo diagnostico (--check): comprueba el entorno sin abrir la TUI.

Uso:
    sudo python3 -m wifi_audit --check
    sudo python3 -m wifi_audit --check --no-monitor   # omite la prueba de modo monitor
"""

from __future__ import annotations

import sys

from .config import VERSION, is_root
from .core import interface as iface_mod
from .core.runner import CommandError, is_available, run_blocking
from .core.tools import detect_tools

# Adaptadores USB WiFi conocidos: {id_vendor:id_product: (nombre, monitor_ok)}
# monitor_ok: True = compatible (captura en modo monitor), False = limitado,
#             None = desconocido / no verificado.
KNOWN_USB_WIRELESS: dict[str, tuple[str, bool | None]] = {
    "0cf3:9271": ("Atheros AR9271", True),
    "148f:5370": ("Ralink RT5370", True),
    "148f:3070": ("Ralink RT3070", True),
    "148f:2870": ("Ralink RT2870", True),
    "0bda:8812": ("Realtek RTL8812AU", True),
    "0bda:8811": ("Realtek RTL8811AU", True),
    "0bda:8187": ("Realtek RTL8187", True),
    "7392:7811": ("Edimax EW-7811Un (RTL8192CU)", True),
    "0e8d:7961": ("MediaTek MT7921U", False),
    "0e8d:7663": ("MediaTek MT7663", None),
    "0e8d:7612": ("MediaTek MT7612U", None),
}

# Vendors habituales de adaptadores WiFi USB (para marcar los "desconocidos").
WIRELESS_USB_VENDORS = {"0cf3", "148f", "0bda", "0e8d", "0846", "7392", "2357"}


def classify_usb_id(usb_id: str) -> tuple[str, bool | None]:
    """Devuelve (nombre, monitor_ok) para un ``usb_id`` tipo ``xxxx:yyyy``."""
    usb_id = usb_id.lower()
    if usb_id in KNOWN_USB_WIRELESS:
        return KNOWN_USB_WIRELESS[usb_id]
    vendor = usb_id.split(":")[0]
    if vendor in WIRELESS_USB_VENDORS:
        return ("Adaptador inalambrico desconocido", None)
    return ("", None)


def _lsusb_output() -> str:
    if not is_available("lsusb"):
        return ""
    try:
        return run_blocking(["lsusb"], timeout=10).output
    except (CommandError, Exception):
        return ""


def detect_wireless_adapters() -> list[tuple[str, str, bool | None]]:
    """Devuelve [(usb_id, nombre, monitor_ok)] de los adaptadores USB WiFi."""
    out = _lsusb_output()
    found: list[tuple[str, str, bool | None]] = []
    for line in out.splitlines():
        parts = line.split()
        try:
            idx = parts.index("ID")
        except ValueError:
            continue
        usb_id = parts[idx + 1].lower()
        vendor = usb_id.split(":")[0]
        if vendor not in WIRELESS_USB_VENDORS:
            continue
        name, ok = classify_usb_id(usb_id)
        if not name:
            name = " ".join(parts[idx + 2 :])
        found.append((usb_id, name, ok))
    return found


def check_python() -> tuple[str, bool]:
    v = sys.version_info
    ok = v >= (3, 10)
    return f"Python {v.major}.{v.minor}.{v.micro} (requiere >= 3.10)", ok


def check_deps() -> tuple[str, bool]:
    missing: list[str] = []
    for mod in ("textual", "rich"):
        try:
            __import__(mod)
        except Exception:
            missing.append(mod)
    if missing:
        return "Dependencias Python (textual, rich): faltan " + ", ".join(missing), False
    return "Dependencias Python (textual, rich)", True


def check_suite() -> tuple[str, bool]:
    tools = detect_tools()
    missing = [n for n, st in tools.items() if not st.available]
    if missing:
        return "Suite aircrack-ng: faltan " + ", ".join(missing), False
    return "Suite aircrack-ng: completa", True


def check_monitor(iface: str) -> tuple[str, bool]:
    """Prueba activar modo monitor y revierte a managed. Devuelve (mensaje, ok)."""
    detail = ""
    try:
        if iface_mod.is_monitor(iface):
            return f"Modo monitor en {iface}: ya activo", True
        run_blocking(["ip", "link", "set", iface, "down"], timeout=10)
        run_blocking(["iw", "dev", iface, "set", "type", "monitor"], timeout=10)
        run_blocking(["ip", "link", "set", iface, "up"], timeout=10)
        ok = iface_mod.is_monitor(iface)
    except Exception as exc:  # noqa: BLE001
        ok = False
        detail = str(exc)
    finally:
        # Revertir a managed en cualquier caso.
        try:
            run_blocking(["ip", "link", "set", iface, "down"], timeout=10)
            run_blocking(["iw", "dev", iface, "set", "type", "managed"], timeout=10)
            run_blocking(["ip", "link", "set", iface, "up"], timeout=10)
        except Exception:
            pass
    if ok:
        return f"Modo monitor en {iface}: OK (revertido)", True
    return f"Modo monitor en {iface}: FALLO ({detail})", False


def run_check(include_monitor: bool = True) -> int:
    """Ejecuta el diagnostico e imprime un informe. Devuelve el exit code."""
    OK = "\033[92mOK\033[0m"
    WARN = "\033[93mWARN\033[0m"
    FAIL = "\033[91mFAIL\033[0m"

    title = f"WiFi Audit TUI v{VERSION} — Diagnóstico"
    print("=" * len(title))
    print(title)
    print("=" * len(title))

    count_ok = count_fail = count_warn = 0
    critical_fail = False

    def report(ok: bool | None, msg: str, critical: bool = False) -> None:
        nonlocal count_ok, count_fail, count_warn, critical_fail
        if ok is True:
            status = OK
            count_ok += 1
        elif ok is False:
            status = FAIL
            count_fail += 1
            if critical:
                critical_fail = True
        else:
            status = WARN
            count_warn += 1
        print(f"[{status}]  {msg}")

    # 1. Python
    msg, ok = check_python()
    report(ok, msg, critical=True)

    # 2. Privilegios
    root = is_root()
    report(root, f"Privilegios de root: {'si' if root else 'no (se recomienda sudo)'}")

    # 3. Dependencias Python
    msg, ok = check_deps()
    report(ok, msg, critical=True)

    # 4. Suite aircrack-ng
    msg, ok = check_suite()
    report(ok, msg, critical=True)

    # 5. Interfaces wireless
    ifaces = iface_mod.list_wireless_interfaces()
    if ifaces:
        report(True, "Interfaces wireless: " + ", ".join(ifaces))
    else:
        report(None, "No se detectaron interfaces wireless")

    # 6. Adaptadores USB WiFi (chipset)
    adapters = detect_wireless_adapters()
    if adapters:
        for usb_id, name, monitor_ok in adapters:
            if monitor_ok is True:
                report(True, f"Adaptador {name} ({usb_id}): compatible con modo monitor")
            elif monitor_ok is False:
                report(None, f"Adaptador {name} ({usb_id}): modo monitor LIMITADO (no captura frames)")
            else:
                report(None, f"Adaptador {name} ({usb_id}): compatibilidad no verificada")
    else:
        report(None, "No se detecto adaptador USB WiFi (pasa el adaptador a la VM)")

    # 7. Prueba de modo monitor (requiere root + interfaz)
    if include_monitor:
        if not ifaces:
            report(None, "Prueba de modo monitor omitida (sin interfaz wireless)")
        elif not root:
            report(None, "Prueba de modo monitor omitida (requiere root)")
        else:
            msg, ok = check_monitor(ifaces[0])
            report(ok, msg)

    print("-" * len(title))
    print(f"Resultado: {count_ok} OK, {count_fail} FAIL, {count_warn} WARN")
    if critical_fail:
        print("Diagnostico: HAY FALLOS CRITICOS.")
        return 1
    return 0
