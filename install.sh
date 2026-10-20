#!/usr/bin/env bash
# Instalador de WiFi Audit TUI (Kali / Debian).
#
# Uso:
#   curl -sSL https://raw.githubusercontent.com/FerminGonzalez/wifi-audit-tui/main/install.sh | sudo bash
#   # o, dentro del repositorio:
#   sudo ./install.sh
set -euo pipefail

REPO_URL="https://github.com/FerminGonzalez/wifi-audit-tui.git"
APP_DIR="$HOME/wifi-audit-tui"

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Se requieren privilegios de root. Reejecutando con sudo..."
    exec sudo -E "$0" "$@"
fi

echo "==> 1/4 Instalando dependencias del sistema (aircrack-ng, textual, rich)..."
apt-get update -y
apt-get install -y aircrack-ng python3 python3-textual python3-rich git

echo "==> 2/4 Obteniendo el codigo..."
if [ -d "$APP_DIR/.git" ]; then
    git -C "$APP_DIR" pull
else
    rm -rf "$APP_DIR"
    git clone --depth 1 "$REPO_URL" "$APP_DIR"
fi

echo "==> 3/4 Instalando icono y launcher de escritorio..."
mkdir -p "$HOME/.local/share/icons/hicolor/scalable/apps"
cp "$APP_DIR/assets/wifi-audit-tui.svg" "$HOME/.local/share/icons/hicolor/scalable/apps/wifi-audit-tui.svg"

mkdir -p "$HOME/.local/share/applications"
cp "$APP_DIR/assets/wifi-audit-tui.desktop" "$HOME/.local/share/applications/"
chmod +x "$HOME/.local/share/applications/wifi-audit-tui.desktop"

DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"
mkdir -p "$DESKTOP_DIR"
cp "$APP_DIR/assets/wifi-audit-tui.desktop" "$DESKTOP_DIR/wifi-audit-tui.desktop"
chmod +x "$DESKTOP_DIR/wifi-audit-tui.desktop"

echo "==> 4/4 Verificando la instalacion..."
cd "$APP_DIR"
python3 -m wifi_audit --check || true

echo ""
echo "Listo. Lanza la TUI con:"
echo "  sudo python3 -m wifi_audit"
echo "  # o el icono 'WiFi Audit TUI' en el menu de aplicaciones / escritorio."
