"""Capa opcional de IA sobre una API compatible con OpenAI.

Sirve tanto para un Ollama local (``/v1/chat/completions``) como para una
API remota (DeepSeek, OpenAI, Groq...). No anade dependencias: usa ``urllib``.

La IA es siempre **consejera**: si no esta disponible, falla o devuelve algo
invalido, el orquestador continua con su tabla de decision determinista. Nunca
es la unica barrera de seguridad.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from ..config import (
    AI_API_KEY,
    AI_BASE_URL,
    AI_MODE,
    AI_MODEL,
    AI_TIMEOUT,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
)

# Enfoques que la IA puede recomendar. Cualquier otro se descarta.
ALLOWED_APPROACHES = {
    "pmkid",
    "handshake",
    "wep",
    "unsupported",
    "open",
}

_SYSTEM = (
    "Eres un asistente experto en auditoria Wi-Fi autorizada sobre la suite "
    "aircrack-ng. Trabajas exclusivamente sobre redes propias o con "
    "autorizacion escrita. Eres preciso, breve y nunca inventas datos: si no "
    "sabes algo, lo indicas."
)


class AIError(RuntimeError):
    """La capa de IA no esta disponible o devolvio una respuesta invalida."""


@dataclass
class Backend:
    kind: str
    base_url: str
    model: str
    api_key: str

    @property
    def endpoint(self) -> str:
        return self.base_url.rstrip("/") + "/chat/completions"


def resolve_backend() -> Backend | None:
    """Resuelve el backend segun WIFI_AUDIT_AI. None si la IA esta desactivada."""
    mode = (AI_MODE or "auto").lower()
    if mode == "off":
        return None
    if mode == "ollama":
        return Backend("ollama", AI_BASE_URL or OLLAMA_BASE_URL,
                       AI_MODEL or OLLAMA_MODEL, AI_API_KEY or "ollama")
    if mode == "api":
        if not AI_BASE_URL:
            return None
        return Backend("api", AI_BASE_URL, AI_MODEL or "gpt-4o-mini", AI_API_KEY)
    # auto: si hay URL explicita -> API; si no, intenta Ollama local.
    if AI_BASE_URL:
        return Backend("api", AI_BASE_URL, AI_MODEL or "gpt-4o-mini", AI_API_KEY)
    return Backend("ollama", OLLAMA_BASE_URL, AI_MODEL or OLLAMA_MODEL,
                   AI_API_KEY or "ollama")


def available() -> bool:
    return resolve_backend() is not None


def describe_backend() -> str:
    backend = resolve_backend()
    if backend is None:
        return "IA desactivada"
    return f"IA {backend.kind}: {backend.model} @ {backend.base_url}"


# --------------------------------------------------------------------- HTTP
def _chat(messages: list[dict[str, str]], *, temperature: float = 0.2,
          max_tokens: int = 800) -> str:
    backend = resolve_backend()
    if backend is None:
        raise AIError("La capa de IA esta desactivada (WIFI_AUDIT_AI=off).")

    payload = {
        "model": backend.model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        backend.endpoint,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {backend.api_key}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise AIError(f"HTTP {exc.code} de la API de IA: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AIError(f"No se pudo contactar con la IA: {exc}") from exc

    try:
        parsed = json.loads(body)
        content = parsed["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise AIError("Respuesta de IA con formato inesperado.") from exc
    return str(content).strip()


def _extract_json(text: str) -> dict[str, Any]:
    """Extrae el primer objeto JSON de la respuesta (tolera ```json ... ```)."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise AIError("La IA no devolvio JSON.")
    try:
        return json.loads(match.group(0))
    except ValueError as exc:
        raise AIError("JSON devuelto por la IA invalido.") from exc


# ------------------------------------------------------------- operaciones
def plan_target(fingerprint: dict[str, Any],
                clients: list[dict[str, Any]],
                fallback: dict[str, Any]) -> dict[str, Any]:
    """Pide a la IA el enfoque para un AP. Devuelve dict validado.

    ``fallback`` es el plan determinista; se usa si la IA no responde o
    propone algo fuera de la lista permitida.
    """
    prompt = (
        "Elige el enfoque de auditoria para este punto de acceso. "
        f"Enfoques permitidos: {sorted(ALLOWED_APPROACHES)}.\n\n"
        f"AP: {json.dumps(fingerprint, ensure_ascii=False)}\n"
        f"Clientes asociados: {json.dumps(clients, ensure_ascii=False)}\n"
        f"Plan determinista de referencia: {json.dumps(fallback, ensure_ascii=False)}\n\n"
        "Devuelve SOLO JSON con las claves: approach (uno de los permitidos), "
        "rationale (texto breve en espanol) y steps (lista de cadenas)."
    )
    content = _chat(
        [{"role": "system", "content": _SYSTEM},
         {"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=400,
    )
    data = _extract_json(content)
    approach = str(data.get("approach", "")).strip().lower()
    if approach not in ALLOWED_APPROACHES:
        raise AIError(f"Enfoque no permitido: {approach!r}")
    return {
        "approach": approach,
        "rationale": str(data.get("rationale", "")).strip(),
        "steps": [str(s) for s in data.get("steps", []) if str(s).strip()],
    }


def interpret_results(summary: dict[str, Any]) -> str:
    """Explica en lenguaje natural que ha pasado en la sesion."""
    prompt = (
        "Resume los resultados de esta auditoria Wi-Fi. Explica que se capturo, "
        "si se recupero alguna clave, que fallo y por que. Se conciso (max 250 "
        "palabras) y en espanol.\n\n"
        f"Datos: {json.dumps(summary, ensure_ascii=False)}"
    )
    return _chat(
        [{"role": "system", "content": _SYSTEM},
         {"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=600,
    )


def generate_report_analysis(summary: dict[str, Any]) -> str:
    """Genera la seccion de analisis para el informe (hallazgos + remediacion)."""
    prompt = (
        "Redacta en Markdown la seccion 'Analisis y recomendaciones' del informe "
        "de auditoria. Incluye: hallazgos de riesgo por AP (cifrado, WPS, red "
        "abierta, WPA3), resultado del cracking y recomendaciones de remediacion "
        "priorizadas. En espanol, tono profesional, sin inventar datos.\n\n"
        f"Datos: {json.dumps(summary, ensure_ascii=False)}"
    )
    return _chat(
        [{"role": "system", "content": _SYSTEM},
         {"role": "user", "content": prompt}],
        temperature=0.3,
        max_tokens=1000,
    )
