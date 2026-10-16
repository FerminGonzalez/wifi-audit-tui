"""Modal de autorizacion obligatoria antes de cualquier operacion."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static

from ..auth import AUTH_PHRASE, LEGAL_NOTICE


class AuthorizationScreen(ModalScreen[bool]):
    """Pide confirmacion explicita de autorizacion escrita.

    dismiss(True) si el operador confirma, dismiss(False) si decide salir.
    """

    BINDINGS = [("escape", "decline", "Salir")]

    def compose(self) -> ComposeResult:
        with Vertical(id="auth-box"):
            yield Label("AVISO LEGAL Y CONFIRMACION DE AUTORIZACION", id="auth-title")
            yield Static(LEGAL_NOTICE, id="auth-text")
            yield Label(
                f"Escribe  {AUTH_PHRASE}  para confirmar que tienes autorizacion:",
                id="auth-prompt",
            )
            yield Input(placeholder=AUTH_PHRASE, id="auth-input")
            with Horizontal(id="auth-buttons"):
                yield Button("Salir", id="auth-exit", variant="error")
                yield Button("Confirmar", id="auth-ok", variant="success", disabled=True)

    def on_mount(self) -> None:
        self.query_one("#auth-input", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        ok = event.value.strip().upper() == AUTH_PHRASE
        self.query_one("#auth-ok", Button).disabled = not ok

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "auth-ok":
            self.dismiss(True)
        else:
            self.dismiss(False)

    def action_decline(self) -> None:
        self.dismiss(False)
