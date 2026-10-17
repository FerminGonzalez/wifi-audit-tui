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
                f"Escribe  {AUTH_PHRASE}  (en mayusculas) y pulsa ENTER, "
                "o haz clic en Confirmar:",
                id="auth-prompt",
            )
            yield Input(placeholder=AUTH_PHRASE, id="auth-input")
            with Horizontal(id="auth-buttons"):
                yield Button("Salir (Esc)", id="auth-exit", variant="error")
                yield Button("Confirmar (Enter)", id="auth-ok", variant="success", disabled=True)

    def on_mount(self) -> None:
        self.query_one("#auth-input", Input).focus()

    @staticmethod
    def _is_ok(value: str) -> bool:
        return value.strip().upper() == AUTH_PHRASE

    def on_input_changed(self, event: Input.Changed) -> None:
        self.query_one("#auth-ok", Button).disabled = not self._is_ok(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if self._is_ok(event.value):
            self.dismiss(True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "auth-ok":
            self.dismiss(True)
        else:
            self.dismiss(False)

    def action_decline(self) -> None:
        self.dismiss(False)
