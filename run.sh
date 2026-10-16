#!/usr/bin/env bash
# Lanzador de WiFi Audit TUI.
# La suite aircrack-ng requiere privilegios de root para modo monitor e inyeccion.

set -euo pipefail
cd "$(dirname "$0")"

if [ "${1:-}" = "--help" ]; then
    echo "Uso: ./run.sh"
    echo "Ejecuta la TUI. Si no eres root, se reejecuta con sudo."
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Se requieren privilegios de root. Reejecutando con sudo..."
    exec sudo -E "$(command -v python3)" -m wifi_audit "$@"
fi

exec python3 -m wifi_audit "$@"
