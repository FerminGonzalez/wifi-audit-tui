"""Ejecucion de subprocesos con streaming y apagado limpio."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional


class CommandError(RuntimeError):
    """El comando no existe o no se pudo iniciar."""


def ensure_available(name: str) -> str:
    """Devuelve la ruta del ejecutable o lanza CommandError."""
    path = shutil.which(name)
    if not path:
        raise CommandError(f"Comando no encontrado en PATH: {name}")
    return path


def is_available(name: str) -> bool:
    return shutil.which(name) is not None


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    output: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class ManagedProcess:
    """Envuelve subprocess.Popen con streaming de lineas y parada por grupo.

    Usa ``start_new_session=True`` para crear un grupo de procesos, de forma
    que podamos terminar tambien a los hijos (p. ej. los que lanza aireplay-ng).
    """

    def __init__(self, argv: Iterable[str], log_file: Optional[Path] = None):
        self.argv = [str(a) for a in argv]
        self.log_file = Path(log_file) if log_file else None
        self._proc: Optional[subprocess.Popen] = None
        self._log_handle = None
        self._stopped = False

    # -- ciclo de vida -----------------------------------------------------
    def start(self) -> "ManagedProcess":
        ensure_available(self.argv[0])
        stdout_target: object = subprocess.PIPE
        if self.log_file is not None:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            self._log_handle = open(
                self.log_file, "w", buffering=1, encoding="utf-8", errors="replace"
            )
            stdout_target = self._log_handle

        self._proc = subprocess.Popen(
            self.argv,
            stdin=subprocess.DEVNULL,
            stdout=stdout_target,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        return self

    @property
    def pid(self) -> Optional[int]:
        return self._proc.pid if self._proc else None

    def poll(self) -> Optional[int]:
        return self._proc.poll() if self._proc else None

    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def lines(self) -> Iterator[str]:
        """Genera las lineas de salida conforme llegan."""
        if self._proc is None or self._proc.stdout is None:
            return
        try:
            for raw in iter(self._proc.stdout.readline, ""):
                if self._stopped:
                    break
                yield raw.rstrip("\r\n")
        finally:
            try:
                self._proc.stdout.close()
            except Exception:
                pass

    def wait(self, timeout: Optional[float] = None) -> int:
        if self._proc is None:
            return -1
        return self._proc.wait(timeout=timeout)

    def stop(self) -> None:
        """Termina el proceso (y su grupo) de forma ordenada."""
        self._stopped = True
        if self._proc and self._proc.poll() is None:
            self._signal(signal.SIGTERM)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._signal(signal.SIGKILL)
                try:
                    self._proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
        self._close_log()

    def _signal(self, sig: int) -> None:
        if not self._proc:
            return
        try:
            os.killpg(os.getpgid(self._proc.pid), sig)
        except (ProcessLookupError, PermissionError):
            try:
                self._proc.send_signal(sig)
            except Exception:
                pass

    def _close_log(self) -> None:
        if self._log_handle:
            try:
                self._log_handle.close()
            except Exception:
                pass
            self._log_handle = None


def run_blocking(argv: Iterable[str], timeout: float = 30.0) -> CommandResult:
    """Ejecuta un comando corto y devuelve su salida completa."""
    argv = [str(a) for a in argv]
    ensure_available(argv[0])
    proc = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    return CommandResult(argv, proc.returncode, proc.stdout or "")
