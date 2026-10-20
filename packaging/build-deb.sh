#!/usr/bin/env bash
# Construye el paquete .deb de wifi-audit-tui.
# Requiere dpkg-deb (Kali / Debian / WSL-Debian).
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="1.0.0"
ARCH="all"
PKG_NAME="wifi-audit-tui_${VERSION}_${ARCH}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "==> Preparando staging..."
# 1) Paquete Python -> /usr/lib/python3/dist-packages
mkdir -p "$STAGE/usr/lib/python3/dist-packages"
cp -r wifi_audit "$STAGE/usr/lib/python3/dist-packages/wifi_audit"
# Limpiar bytecode (no debe viajar en el .deb)
find "$STAGE/usr/lib/python3/dist-packages/wifi_audit" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find "$STAGE/usr/lib/python3/dist-packages/wifi_audit" -name '*.pyc' -delete 2>/dev/null || true

# 2) Wrapper -> /usr/bin
mkdir -p "$STAGE/usr/bin"
install -m 755 packaging/wifi-audit-tui "$STAGE/usr/bin/wifi-audit-tui"

# 3) Launcher + icono
mkdir -p "$STAGE/usr/share/applications" "$STAGE/usr/share/icons/hicolor/scalable/apps"
install -m 644 packaging/wifi-audit-tui.desktop "$STAGE/usr/share/applications/wifi-audit-tui.desktop"
install -m 644 assets/wifi-audit-tui.svg "$STAGE/usr/share/icons/hicolor/scalable/apps/wifi-audit-tui.svg"

# 4) Control
mkdir -p "$STAGE/DEBIAN"
cp packaging/control "$STAGE/DEBIAN/control"

# 5) Construir
mkdir -p dist
dpkg-deb --root-owner-group --build "$STAGE" "dist/${PKG_NAME}.deb"

echo "==> Paquete generado: dist/${PKG_NAME}.deb"
