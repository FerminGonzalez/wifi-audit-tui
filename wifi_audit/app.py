"""Punto de entrada de la aplicacion WiFi Audit TUI."""

from __future__ import annotations

import sys
from typing import Optional

from textual import work
from textual.app import App

from .config import APP_NAME, VERSION, new_session_dir, now_iso
from .core.runner import ManagedProcess
from .screens.authorization import AuthorizationScreen
from .screens.main import MainScreen
from .state import AppState


class WifiAuditApp(App):
    CSS_PATH = "app.tcss"
    TITLE = f"{APP_NAME} v{VERSION}"
    SUB_TITLE = "Auditoria Wi-Fi autorizada sobre la suite aircrack-ng"
    SCREENS = {"main": MainScreen}
    BINDINGS = [("ctrl+q", "quit", "Salir"),
                ("f9", "start_auto", "Auditoria auto")]

    def __init__(self) -> None:
        super().__init__()
        self.state = AppState(session_dir=new_session_dir())
        # Procesos de larga duracion en curso: scan, capture, crack, fakeap
        self.procs: dict[str, ManagedProcess] = {}

    # --------------------------------------------------------------- montaje
    @work
    async def on_mount(self) -> None:
        self.push_screen("main")
        authorized = await self.push_screen_wait(AuthorizationScreen())
        if not authorized:
            self.log_line("Operador no confirmo autorizacion. Saliendo.")
            self.exit()
            return
        self.state.authorized = True
        self.state.auth_timestamp = now_iso()
        self.log_event("Autorizacion confirmada por el operador")

    # ---------------------------------------------------------------- utils
    def log_line(self, text: str) -> None:
        try:
            from textual.widgets import RichLog

            self.query_one("#main-log", RichLog).write(text)
        except Exception:
            pass

    def log_event(self, text: str) -> None:
        self.state.events.append(f"{now_iso()}  {text}")
        self.log_line(f"* {text}")

    def action_start_auto(self) -> None:
        """F9: lanza la auditoria automatica desde la pestana activa."""
        screen = self.screen
        trigger = getattr(screen, "trigger_auto", None)
        if callable(trigger):
            trigger()

    def on_unmount(self) -> None:
        """Garantiza que no dejamos procesos de la suite corriendo."""
        for proc in self.procs.values():
            try:
                proc.stop()
            except Exception:
                pass
        self.procs.clear()


def main() -> None:
    if any(arg in sys.argv[1:] for arg in ("--check", "--diagnose", "-c", "check")):
        from .diagnostics import run_check

        include_monitor = "--no-monitor" not in sys.argv[1:]
        raise SystemExit(run_check(include_monitor=include_monitor))
    WifiAuditApp().run()


if __name__ == "__main__":
    main()
