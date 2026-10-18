"""Generacion del informe de auditoria en Markdown y HTML."""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from .scanner import AccessPoint, Client


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_Sin datos_\n"
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        cells = [str(c).replace("|", "\\|") for c in row]
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"


def render_markdown(
    meta: dict,
    aps: dict[str, AccessPoint],
    clients: dict[str, Client],
    cracks: list[dict],
    attacks: list[str],
    events: list[str],
    ai_analysis: str | None = None,
) -> str:
    lines: list[str] = []
    lines.append("# Informe de auditoria Wi-Fi\n")
    lines.append(f"- **Generado:** {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"- **Sesion:** `{meta.get('session_dir', '')}`")
    lines.append(f"- **Interfaz fisica:** `{meta.get('iface') or 'n/d'}`")
    lines.append(f"- **Interfaz monitor:** `{meta.get('monitor_iface') or 'n/d'}`")
    lines.append(f"- **Autorizacion confirmada:** {meta.get('authorized')}")
    if meta.get("auth_timestamp"):
        lines.append(f"- **Fecha de autorizacion:** {meta['auth_timestamp']}")
    lines.append("")

    lines.append("## Resumen\n")
    lines.append(f"- Puntos de acceso detectados: **{len(aps)}**")
    lines.append(f"- Clientes detectados: **{len(clients)}**")
    lines.append(f"- Handshakes/claves recuperadas: **{len(cracks)}**")
    lines.append(f"- Operaciones activas ejecutadas: **{len(attacks)}**")
    lines.append("")

    lines.append("## Puntos de acceso\n")
    ap_rows = []
    for ap in sorted(aps.values(), key=lambda a: -(int(a.power) if a.power.lstrip("-").isdigit() else -999)):
        ap_rows.append([
            ap.bssid, ap.display_essid, ap.channel, ap.encryption,
            ap.cipher or "-", ap.auth or "-", ap.power or "-",
            ap.beacons, ap.data, str(len(ap.clients)),
        ])
    lines.append(_md_table(
        ["BSSID", "ESSID", "CH", "Cifrado", "Cipher", "Auth", "PWR", "Beacons", "Data", "Clientes"],
        ap_rows,
    ))

    lines.append("\n## Clientes detectados\n")
    cl_rows = [[c.mac, c.bssid or "-", c.power or "-", c.packets, c.probed or "-"]
               for c in clients.values()]
    lines.append(_md_table(["MAC", "AP asociado", "PWR", "Paquetes", "Probes"], cl_rows))

    lines.append("\n## Cracking\n")
    crack_rows = [[c.get("capfile", ""), c.get("bssid", "") or "-",
                   c.get("status", ""), c.get("key", "") or "-", c.get("timestamp", "")]
                  for c in cracks]
    lines.append(_md_table(["Captura", "BSSID", "Resultado", "Clave", "Fecha"], crack_rows))

    lines.append("\n## Operaciones activas\n")
    if attacks:
        for entry in attacks:
            lines.append(f"- {entry}")
        lines.append("")
    else:
        lines.append("_Ninguna_\n")

    lines.append("## Cronologia\n")
    for ev in events:
        lines.append(f"- {ev}")
    lines.append("")

    if ai_analysis:
        lines.append("## Analisis asistido por IA\n")
        lines.append(ai_analysis.strip())
        lines.append("")

    lines.append("---\n")
    lines.append("_Informe generado por WiFi Audit TUI. Uso exclusivo en redes "
                 "propias o con autorizacion escrita._\n")
    return "\n".join(lines)


def _html_escape_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "<p><em>Sin datos</em></p>"
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = ""
    for row in rows:
        body += "<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in row) + "</tr>"
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_html(markdown_text: str) -> str:
    """Envoltura HTML simple con el markdown en <pre> legible si no hay parser.

    Evitamos dependencias externas: mostramos el informe en un bloque
    preformateado con estilo, suficiente para imprimir a PDF desde navegador.
    """
    escaped = html.escape(markdown_text)
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>Informe de auditoria Wi-Fi</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 60rem;
        background:#0f1117; color:#e6e6e6; }}
 h1,h2 {{ color:#7ee787; }}
 pre {{ white-space: pre-wrap; background:#161b22; padding:1rem;
        border:1px solid #30363d; border-radius:8px; line-height:1.5; }}
 .meta {{ color:#8b949e; font-size:.85rem; }}
</style></head>
<body>
<h1>Informe de auditoria Wi-Fi</h1>
<p class="meta">Generado por WiFi Audit TUI &mdash; uso en redes propias o autorizadas.</p>
<pre>{escaped}</pre>
</body></html>
"""


def write_report(
    session_dir: Path,
    meta: dict,
    aps: dict[str, AccessPoint],
    clients: dict[str, Client],
    cracks: list[dict],
    attacks: list[str],
    events: list[str],
    ai_analysis: str | None = None,
) -> tuple[Path, Path]:
    md_path = session_dir / "report.md"
    html_path = session_dir / "report.html"
    markdown_text = render_markdown(meta, aps, clients, cracks, attacks, events,
                                    ai_analysis=ai_analysis)
    md_path.write_text(markdown_text, encoding="utf-8")
    html_path.write_text(render_html(markdown_text), encoding="utf-8")
    return md_path, html_path
