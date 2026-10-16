"""Servidor web de la interfaz de auditoria Wi-Fi.

Usa exclusivamente la libreria estandar (http.server), de modo que puede
ejecutarse incluso en Windows sin instalar dependencias. Las operaciones
sobre la suite aircrack-ng requieren Linux y privilegios de root: si faltan,
la interfaz funciona igual pero avisa y las acciones devuelven error.

Seguridad:
  * Por defecto escucha SOLO en 127.0.0.1.
  * Si se expone en otra interfaz (--host 0.0.0.0) se genera/requiere un
    token que debe enviarse en la cabecera X-Auth-Token o como ?token=.
  * Exige la confirmacion de autorizacion antes de operar.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..config import APP_NAME, VERSION, new_session_dir
from ..core.controller import SessionController
from ..state import AppState

STATIC_DIR = Path(__file__).parent / "static"
INDEX_FILE = STATIC_DIR / "index.html"

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class ApiHandler(BaseHTTPRequestHandler):
    controller: SessionController
    token: str | None = None
    server_version = f"WifiAuditTUI/{VERSION}"

    # ------------------------------------------------------------ respuestas
    def _send_json(self, payload: dict, code: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, text: str, code: int = 200) -> None:
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text: str, code: int = 200) -> None:
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -------------------------------------------------------------- seguridad
    def _token_ok(self, query: dict) -> bool:
        if not self.token:
            return True
        header = self.headers.get("X-Auth-Token")
        if header and secrets.compare_digest(header, self.token):
            return True
        qs_token = (query.get("token") or [""])[0]
        return bool(qs_token) and secrets.compare_digest(qs_token, self.token)

    def _require_authorized(self) -> bool:
        if not self.controller.state.authorized:
            self._send_json(
                {"ok": False, "error": "Debes confirmar la autorizacion primero"},
                code=403,
            )
            return False
        return True

    # ------------------------------------------------------------------- body
    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    # --------------------------------------------------------------------- GET
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if not self._token_ok(query):
            self._send_json({"ok": False, "error": "Token invalido"}, code=401)
            return

        if parsed.path in ("/", "/index.html"):
            if not INDEX_FILE.is_file():
                self._send_text("index.html no encontrado", code=500)
                return
            self._send_html(INDEX_FILE.read_text(encoding="utf-8"))
            return
        if parsed.path == "/api/state":
            self._send_json({"ok": True, "state": self.controller.snapshot()})
            return
        if parsed.path == "/health":
            self._send_json({"ok": True, "version": VERSION, "app": APP_NAME})
            return
        self._send_json({"ok": False, "error": "Ruta no encontrada"}, code=404)

    # -------------------------------------------------------------------- POST
    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if not self._token_ok(query):
            self._send_json({"ok": False, "error": "Token invalido"}, code=401)
            return

        body = self._read_json()
        c = self.controller

        if parsed.path == "/api/authorize":
            ok, msg = c.authorize(str(body.get("phrase", "")))
            self._send_json({"ok": ok, "message": msg})
            return

        if not self._require_authorized():
            return

        ok, msg = False, "Ruta no encontrada"
        try:
            if parsed.path == "/api/monitor/start":
                ok, msg = c.start_monitor(str(body.get("iface", "")))
            elif parsed.path == "/api/monitor/stop":
                ok, msg = c.stop_monitor()
            elif parsed.path == "/api/monitor/kill":
                ok, msg = c.check_kill()
            elif parsed.path == "/api/scan/start":
                ok, msg = c.start_scan(body.get("channel") or None, body.get("bssid") or None)
            elif parsed.path == "/api/scan/stop":
                c.stop("scan")
                ok, msg = True, "Escaneo detenido"
            elif parsed.path == "/api/target":
                ok, msg = c.set_target(str(body.get("bssid", "")))
            elif parsed.path == "/api/capture/start":
                ok, msg = c.start_capture(body.get("channel") or None)
            elif parsed.path == "/api/capture/stop":
                c.stop("capture")
                ok, msg = True, "Captura detenida"
            elif parsed.path == "/api/attack/deauth":
                client = body.get("client") or None
                try:
                    count = int(body.get("count") or 10)
                except (TypeError, ValueError):
                    count = 10
                ok, msg = c.deauth(client, count)
            elif parsed.path == "/api/attack/fakeauth":
                ok, msg = c.fakeauth()
            elif parsed.path == "/api/attack/arpreplay":
                ok, msg = c.arpreplay()
            elif parsed.path == "/api/crack/start":
                ok, msg = c.start_crack(str(body.get("capfile", "")),
                                        str(body.get("wordlist", "")))
            elif parsed.path == "/api/crack/stop":
                c.stop("crack")
                ok, msg = True, "Cracking detenido"
            elif parsed.path == "/api/fakeap/start":
                ch = body.get("channel")
                try:
                    channel = int(ch) if ch not in (None, "") else None
                except (TypeError, ValueError):
                    channel = None
                ok, msg = c.start_fakeap(str(body.get("essid", "")), channel)
            elif parsed.path == "/api/fakeap/stop":
                c.stop("fakeap")
                ok, msg = True, "AP falso detenido"
            elif parsed.path == "/api/report":
                ok, info = c.generate_report()
                self._send_json({"ok": ok, "message": "Informe generado" if ok else "Error",
                                 "info": info})
                return
            else:
                self._send_json({"ok": False, "error": "Ruta no encontrada"}, code=404)
                return
        except Exception as exc:  # noqa: BLE001
            self._send_json({"ok": False, "error": str(exc)}, code=500)
            return

        self._send_json({"ok": ok, "message": msg})

    # -------------------------------------------------------------- silencio
    def log_message(self, *args) -> None:  # noqa: D401
        """Silencia el log por peticion del servidor base."""
        return


def build_server(host: str, port: int, controller: SessionController,
                 token: str | None) -> ThreadingHTTPServer:
    handler = type("BoundApiHandler", (ApiHandler,), {"controller": controller, "token": token})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="wifi-audit-web",
        description="Interfaz web de WiFi Audit TUI sobre la suite aircrack-ng.",
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="Direccion de escucha (por defecto 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8730, help="Puerto (por defecto 8730)")
    parser.add_argument("--sessions", default=None,
                        help="Directorio raiz de sesiones (por defecto ~/wifi-audit-sessions)")
    parser.add_argument("--token", default=None,
                        help="Token de acceso. Obligatorio si se expone fuera de localhost.")
    args = parser.parse_args(argv)
    try:  # vaciado inmediato para que el token aparezca aunque se redirija la salida
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass


    if args.sessions:
        from .. import config
        config.SESSION_ROOT = Path(args.sessions)

    token = args.token
    if args.host not in LOOPBACK and not token:
        token = secrets.token_urlsafe(16)
        print("[!] Escuchando fuera de localhost: se ha generado un token de acceso.")
        print(f"[!] Token: {token}")
        print("[!] Abre la URL con ?token=... o pasa la cabecera X-Auth-Token.\n")

    state = AppState(session_dir=new_session_dir())
    controller = SessionController(state)
    httpd = build_server(args.host, args.port, controller, token)

    url = f"http://{args.host if args.host != '0.0.0.0' else 'localhost'}:{args.port}"
    print(f"== {APP_NAME} v{VERSION} - interfaz web ==")
    print(f"   URL       : {url}{('?token=' + token) if token else ''}")
    print(f"   Sesion    : {state.session_dir}")
    print(f"   root      : {'si' if _is_root() else 'NO (necesario para operar)'}")
    print("   Ctrl+C para detener.\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nDeteniendo ...")
    finally:
        controller.shutdown()
        httpd.shutdown()


def _is_root() -> bool:
    from ..config import is_root

    return is_root()


if __name__ == "__main__":
    main(sys.argv[1:])
