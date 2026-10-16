"""Deteccion de las herramientas de la suite en el sistema."""

from __future__ import annotations

import shutil
from dataclasses import dataclass

from ..config import TOOL_NAMES


@dataclass
class ToolStatus:
    name: str
    path: str | None

    @property
    def available(self) -> bool:
        return self.path is not None


def detect_tools() -> dict[str, ToolStatus]:
    return {name: ToolStatus(name, shutil.which(name)) for name in TOOL_NAMES}


def missing_tools() -> list[str]:
    return [name for name, st in detect_tools().items() if not st.available]


def suite_installed() -> bool:
    return not missing_tools()
