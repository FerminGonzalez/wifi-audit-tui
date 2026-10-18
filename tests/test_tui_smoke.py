"""Prueba de humo de la TUI: compone las pestanas y los widgets de Auto + IA.

Se salta automaticamente si Textual no esta instalado.
"""

from __future__ import annotations

import asyncio

import pytest

textual = pytest.importorskip("textual")

from textual.app import App  # noqa: E402
from textual.widgets import TabPane  # noqa: E402

from wifi_audit.config import new_session_dir  # noqa: E402
from wifi_audit.screens.main import MainScreen  # noqa: E402
from wifi_audit.state import AppState  # noqa: E402


class _Host(App):
    SCREENS = {"main": MainScreen}

    def __init__(self) -> None:
        super().__init__()
        self.state = AppState(session_dir=new_session_dir())
        self.state.authorized = True
        self.procs: dict = {}

    def on_mount(self) -> None:
        self.push_screen("main")

    def log_line(self, text: str) -> None:
        pass

    def log_event(self, text: str) -> None:
        self.state.events.append(text)


async def _check() -> None:
    app = _Host()
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        panes = [p.id for p in screen.query(TabPane)]
        assert "tab-auto" in panes
        for wid in ("#auto-wordlist", "#auto-scan-secs", "#auto-cap-secs",
                    "#auto-use-ai", "#btn-auto-start", "#btn-auto-stop",
                    "#auto-log", "#auto-ai-status"):
            screen.query_one(wid)
        assert callable(getattr(screen, "trigger_auto", None))


def test_tui_compone_con_auto():
    asyncio.run(_check())
