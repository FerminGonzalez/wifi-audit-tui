"""Pantalla principal: pestanas para cada fase de la auditoria."""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    Switch,
    TabbedContent,
    TabPane,
)
from textual.worker import get_current_worker

from ..config import is_root, now_iso
from ..core import attacks, ai, cracker, interface, scanner
from ..core.orchestrator import AutoAuditor
from ..core.report import write_report
from ..core.runner import CommandError, ManagedProcess
from ..core.tools import detect_tools

if TYPE_CHECKING:
    from ..app import WifiAuditApp


class MainScreen(Screen):
    app: "WifiAuditApp"

    def __init__(self) -> None:
        super().__init__()
        self._ifaces: list[str] = []
        self._selected_bssid: str | None = None
        self._ap_cols: list[Any] = []
        self._client_cols: list[Any] = []
        self._auto_auditor: AutoAuditor | None = None
        self._auto_stop_requested = False

    # ------------------------------------------------------------------ UI
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="env-status")

        with TabbedContent(id="tabs"):
            with TabPane("1 Interfaz", id="tab-iface"):
                with VerticalScroll():
                    yield Label("Interfaz inalambrica")
                    yield Select([], id="iface-select", prompt="Selecciona interfaz",
                                 allow_blank=True)
                    with Horizontal(classes="row"):
                        yield Button("Refrescar", id="btn-refresh-ifaces")
                        yield Button("check kill", id="btn-kill", variant="warning")
                        yield Button("Iniciar monitor", id="btn-mon-start", variant="success")
                        yield Button("Detener monitor", id="btn-mon-stop", variant="error")
                    yield Static("", id="mon-status")

            with TabPane("2 Escaneo", id="tab-scan"):
                with Vertical():
                    with Horizontal(classes="row"):
                        yield Input(placeholder="Canal (opcional)", id="scan-channel")
                        yield Input(placeholder="BSSID (opcional)", id="scan-bssid")
                        yield Button("Iniciar escaneo", id="btn-scan-start", variant="success")
                        yield Button("Detener", id="btn-scan-stop", variant="error")
                        yield Button("Limpiar", id="btn-scan-clear")
                    yield Static("Puntos de acceso  (usa la flecha y Enter / boton para fijar objetivo)",
                                 classes="hint")
                    yield DataTable(id="ap-table")
                    yield Static("Clientes", classes="hint")
                    yield DataTable(id="client-table")
                    yield Button("Fijar AP seleccionado como objetivo",
                                 id="btn-set-target", variant="primary")

            with TabPane("3 Captura", id="tab-capture"):
                with VerticalScroll():
                    yield Static("Objetivo: (ninguno)", id="target-info")
                    with Horizontal(classes="row"):
                        yield Input(placeholder="Canal", id="cap-channel")
                        yield Button("Iniciar captura", id="btn-cap-start", variant="success")
                        yield Button("Detener captura", id="btn-cap-stop", variant="error")
                        yield Button("Deauth (forzar handshake)", id="btn-deauth-here",
                                     variant="warning")
                    yield Static("", id="cap-status")
                    yield Static("Los ficheros .cap se guardan en la carpeta de sesion.",
                                 classes="hint")

            with TabPane("4 Ataques", id="tab-attack"):
                with VerticalScroll():
                    yield Label("Cliente objetivo (MAC, opcional)")
                    yield Input(placeholder="AA:BB:CC:DD:EE:FF", id="atk-client")
                    with Horizontal(classes="row"):
                        yield Input(placeholder="N de deauths", id="atk-count", value="10")
                        yield Button("Deauth", id="btn-deauth", variant="warning")
                        yield Button("Fake auth", id="btn-fakeauth", variant="warning")
                        yield Button("ARP replay (WEP)", id="btn-arp", variant="warning")
                    yield RichLog(id="atk-log", highlight=True, markup=False, wrap=True)

            with TabPane("5 Cracking", id="tab-crack"):
                with VerticalScroll():
                    yield Label("Diccionario (wordlist)")
                    yield Input(placeholder="/usr/share/wordlists/rockyou.txt", id="wordlist")
                    yield Label("Captura a procesar")
                    yield Select([], id="capfile-select", prompt="Selecciona fichero .cap",
                                 allow_blank=True)
                    with Horizontal(classes="row"):
                        yield Button("Refrescar capturas", id="btn-refresh-caps")
                        yield Button("Iniciar cracking", id="btn-crack-start", variant="success")
                        yield Button("Detener", id="btn-crack-stop", variant="error")
                    yield Static("", id="crack-status")

            with TabPane("6 AP falso", id="tab-fakeap"):
                with VerticalScroll():
                    yield Label("ESSID del AP falso")
                    yield Input(placeholder="MiAP-Audit", id="ap-essid")
                    with Horizontal(classes="row"):
                        yield Input(placeholder="Canal", id="ap-channel")
                        yield Button("Iniciar AP falso", id="btn-ap-start", variant="success")
                        yield Button("Detener", id="btn-ap-stop", variant="error")
                    yield RichLog(id="ap-log", highlight=True, markup=False, wrap=True)

            with TabPane("7 Informe", id="tab-report"):
                with VerticalScroll():
                    with Horizontal(classes="row"):
                        yield Button("Generar informe", id="btn-report", variant="primary")
                    yield Static("", id="report-status")
                    yield Static("", id="report-preview", markup=False)

            with TabPane("8 Registro", id="tab-log"):
                with VerticalScroll():
                    yield RichLog(id="main-log", highlight=True, markup=False, wrap=True)

            with TabPane("9 Auto + IA", id="tab-auto"):
                with VerticalScroll():
                    yield Static("", id="auto-ai-status")
                    yield Label("Diccionario para el cracking automatico (wordlist)")
                    yield Input(placeholder="/usr/share/wordlists/rockyou.txt",
                                id="auto-wordlist")
                    with Horizontal(classes="row"):
                        yield Label("Seg. escaneo")
                        yield Input(value="30", id="auto-scan-secs")
                        yield Label("Seg. captura")
                        yield Input(value="60", id="auto-cap-secs")
                        yield Label("Usar IA")
                        yield Switch(value=True, id="auto-use-ai")
                    yield Static("Flujo completo: interfaz -> escaneo -> objetivo -> "
                                 "metodo (IA/determinista) -> captura/ataque -> "
                                 "cracking -> informe.", classes="hint")
                    with Horizontal(classes="row"):
                        yield Button("Ejecutar auditoria automatica",
                                     id="btn-auto-start", variant="primary")
                        yield Button("Detener", id="btn-auto-stop", variant="error")
                        yield Button("Generar informe", id="btn-auto-report",
                                     variant="success")
                    yield Static("", id="auto-status")
                    yield RichLog(id="auto-log", highlight=True, markup=False, wrap=True)

        yield Footer()

    # ------------------------------------------------------------- montaje
    def on_mount(self) -> None:
        ap_table = self.query_one("#ap-table", DataTable)
        ap_table.cursor_type = "row"
        self._ap_cols = ap_table.add_columns(
            "BSSID", "ESSID", "CH", "Cifrado", "PWR", "Beacons", "Data", "Clientes"
        )
        cl_table = self.query_one("#client-table", DataTable)
        cl_table.cursor_type = "row"
        self._client_cols = cl_table.add_columns(
            "MAC", "AP asociado", "PWR", "Paquetes", "Probes"
        )
        self.refresh_ifaces()
        self.refresh_captures()
        self.update_env()
        try:
            self.query_one("#auto-ai-status", Static).update(
                f"[b]{ai.describe_backend()}[/b]")
        except Exception:
            pass
        self.app.log_line(f"Sesion: {self.app.state.session_dir}")

    # ------------------------------------------------------------- helpers
    def _require_root(self) -> bool:
        if not is_root():
            self.notify("Necesitas privilegios de root (ejecuta con sudo).",
                        severity="error")
            return False
        return True

    def _require_monitor(self) -> bool:
        if not self.app.state.monitor_iface:
            self.notify("No hay interfaz en modo monitor. Activala en la pestana Interfaz.",
                        severity="error")
            return False
        return True

    def _require_target(self) -> bool:
        if not self.app.state.target_bssid:
            self.notify("Fija un AP objetivo primero (pestana Escaneo).",
                        severity="error")
            return False
        return True

    def update_env(self) -> None:
        tools = detect_tools()
        missing = [name for name, st in tools.items() if not st.available]
        root_txt = "si" if is_root() else "[red]NO (usa sudo)[/red]"
        suite = ("[green]suite aircrack-ng: OK[/green]" if not missing
                 else f"[red]faltan: {', '.join(missing)}[/red]")
        st = self.app.state
        text = (
            f"root: {root_txt}  |  {suite}  |  "
            f"iface: {st.iface or '-'}  monitor: {st.monitor_iface or '-'}"
        )
        self.query_one("#env-status", Static).update(text)

    def refresh_ifaces(self) -> None:
        self._ifaces = interface.list_wireless_interfaces()
        sel = self.query_one("#iface-select", Select)
        sel.set_options([(i, i) for i in self._ifaces])
        if not self._ifaces:
            self.notify("No se detectan interfaces inalambricas.", severity="warning")

    def refresh_captures(self) -> None:
        files = scanner.list_capture_files(self.app.state.session_dir)
        sel = self.query_one("#capfile-select", Select)
        sel.set_options([(f.name, str(f)) for f in files])

    def refresh_monitor_status(self) -> None:
        mon = self.app.state.monitor_iface
        widget = self.query_one("#mon-status", Static)
        if mon:
            widget.update(f"Interfaz monitor activa: [green]{mon}[/green]")
        else:
            widget.update("Sin interfaz en modo monitor.")

    # ------------------------------------------------------ autorizacion UI
    def set_target(self, bssid: str) -> None:
        ap = self.app.state.aps.get(bssid)
        if not ap:
            return
        self.app.state.target_bssid = bssid
        self.app.state.target_channel = ap.channel
        self.query_one("#target-info", Static).update(
            f"Objetivo: [b]{ap.display_essid}[/b]   {bssid}   "
            f"canal {ap.channel}   ({ap.encryption})"
        )
        self.query_one("#cap-channel", Input).value = ap.channel or ""
        self.app.log_event(f"Objetivo fijado: {ap.display_essid} ({bssid}) canal {ap.channel}")
        self.notify(f"Objetivo: {ap.display_essid}")

    # ================================================================ Interfaz
    @on(Select.Changed, "#iface-select")
    def _on_iface_changed(self, event: Select.Changed) -> None:
        if event.value is not Select.BLANK and event.value is not None:
            self.app.state.iface = str(event.value)
            self.update_env()

    @on(Button.Pressed, "#btn-refresh-ifaces")
    def _on_refresh_ifaces(self) -> None:
        self.refresh_ifaces()
        self.update_env()

    @on(Button.Pressed, "#btn-kill")
    def _on_kill(self) -> None:
        if not self._require_root():
            return
        self._kill_worker()

    @work(thread=True)
    def _kill_worker(self) -> None:
        try:
            out = interface.check_kill()
        except Exception as exc:  # noqa: BLE001
            self.app.call_from_thread(self.notify, f"Error: {exc}", severity="error")
            return
        self.app.call_from_thread(self.app.log_line, "[check kill]\n" + out)
        self.app.call_from_thread(self.notify, "Procesos interferentes terminados.")

    @on(Button.Pressed, "#btn-mon-start")
    def _on_mon_start(self) -> None:
        if not self._require_root():
            return
        value = self.query_one("#iface-select", Select).value
        if value is Select.BLANK or value is None:
            self.notify("Selecciona una interfaz.", severity="error")
            return
        self.app.log_line(f"[monitor] activando modo monitor en {value} ...")
        self._mon_start_worker(str(value))

    @work(thread=True)
    def _mon_start_worker(self, iface: str) -> None:
        try:
            mon = interface.start_monitor(iface)
            err = None
        except Exception as exc:  # noqa: BLE001
            mon, err = None, str(exc)
        self.app.call_from_thread(self._mon_started, iface, mon, err)

    def _mon_started(self, iface: str, mon: str | None, err: str | None) -> None:
        if err:
            self.notify(f"Error al activar monitor: {err}", severity="error")
        elif mon:
            self.app.state.iface = iface
            self.app.state.monitor_iface = mon
            self.app.log_event(f"Modo monitor activado: {iface} -> {mon}")
            self.notify(f"Monitor activo: {mon}")
        else:
            self.notify("No se pudo activar el modo monitor (revisa el adaptador).",
                        severity="error")
        self.refresh_monitor_status()
        self.update_env()

    @on(Button.Pressed, "#btn-mon-stop")
    def _on_mon_stop(self) -> None:
        if not self._require_root():
            return
        mon = self.app.state.monitor_iface
        if not mon:
            self.notify("No hay monitor activo.", severity="warning")
            return
        self._kill_process("scan")
        self._kill_process("capture")
        self._mon_stop_worker(mon)

    @work(thread=True)
    def _mon_stop_worker(self, mon: str) -> None:
        try:
            interface.stop_monitor(mon)
        except Exception as exc:  # noqa: BLE001
            self.app.call_from_thread(self.notify, f"Error: {exc}", severity="error")
        self.app.call_from_thread(self._mon_stopped, mon)

    def _mon_stopped(self, mon: str) -> None:
        self.app.state.monitor_iface = None
        self.app.log_event(f"Modo monitor desactivado: {mon}")
        self.notify("Modo monitor desactivado.")
        self.refresh_monitor_status()
        self.update_env()

    # ================================================================= Escaneo
    @on(Button.Pressed, "#btn-scan-start")
    def _on_scan_start(self) -> None:
        if not self._require_root() or not self._require_monitor():
            return
        if "scan" in self.app.procs:
            self.notify("Ya hay un escaneo en curso.", severity="warning")
            return
        st = self.app.state
        ch = self.query_one("#scan-channel", Input).value.strip() or None
        bssid = self.query_one("#scan-bssid", Input).value.strip() or None
        prefix = st.session_dir / "scan"
        argv = attacks.scan_argv(st.monitor_iface, prefix, channel=ch, bssid=bssid)
        log = st.session_dir / "scan.stdout.log"
        try:
            proc = ManagedProcess(argv, log_file=log).start()
        except CommandError as exc:
            self.notify(str(exc), severity="error")
            return
        self.app.procs["scan"] = proc
        self.app.log_line(f"[scan] {' '.join(argv)}")
        self.app.log_event(f"Escaneo iniciado en {st.monitor_iface}")
        self._scan_loop(proc, prefix, log)

    @work(thread=True)
    def _scan_loop(self, proc: ManagedProcess, prefix: Path, log: Path) -> None:
        worker = get_current_worker()
        try:
            while not worker.is_cancelled and proc.poll() is None:
                time.sleep(1.0)
                csv_path = scanner.latest_csv(prefix)
                if csv_path:
                    aps, clients = scanner.parse_airodump_csv(csv_path)
                    self.app.call_from_thread(self._apply_scan_update, aps, clients)
        finally:
            proc.stop()
            self.app.call_from_thread(self._scan_finished)

    def _apply_scan_update(self, aps, clients) -> None:
        self.app.state.aps = aps
        self.app.state.clients = clients
        self._render_ap_table()
        self._render_client_table()

    def _render_ap_table(self) -> None:
        table = self.query_one("#ap-table", DataTable)
        existing = set(table.rows.keys())
        current = set(self.app.state.aps.keys())
        for row_key in existing - current:
            try:
                table.remove_row(row_key)
            except Exception:
                pass
        for bssid, ap in self.app.state.aps.items():
            values = (bssid, ap.display_essid, ap.channel, ap.encryption,
                      ap.power, ap.beacons, ap.data, str(len(ap.clients)))
            if bssid in existing:
                for idx, col in enumerate(self._ap_cols):
                    try:
                        table.update_cell(bssid, col, values[idx])
                    except Exception:
                        pass
            else:
                table.add_row(*values, key=bssid)

    def _render_client_table(self) -> None:
        table = self.query_one("#client-table", DataTable)
        existing = set(table.rows.keys())
        current = set(self.app.state.clients.keys())
        for row_key in existing - current:
            try:
                table.remove_row(row_key)
            except Exception:
                pass
        for mac, cl in self.app.state.clients.items():
            values = (mac, cl.bssid or "-", cl.power, cl.packets, cl.probed or "-")
            if mac in existing:
                for idx, col in enumerate(self._client_cols):
                    try:
                        table.update_cell(mac, col, values[idx])
                    except Exception:
                        pass
            else:
                table.add_row(*values, key=mac)

    def _scan_finished(self) -> None:
        self.app.procs.pop("scan", None)
        self.app.log_event("Escaneo detenido")
        self.notify("Escaneo detenido.")

    @on(Button.Pressed, "#btn-scan-stop")
    def _on_scan_stop(self) -> None:
        self._kill_process("scan")

    @on(Button.Pressed, "#btn-scan-clear")
    def _on_scan_clear(self) -> None:
        self.query_one("#ap-table", DataTable).clear()
        self.query_one("#client-table", DataTable).clear()

    @on(DataTable.RowHighlighted, "#ap-table")
    def _on_ap_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is not None:
            self._selected_bssid = str(event.row_key.value)

    @on(DataTable.RowSelected, "#ap-table")
    def _on_ap_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is not None:
            self.set_target(str(event.row_key.value))

    @on(Button.Pressed, "#btn-set-target")
    def _on_set_target(self) -> None:
        bssid = self._selected_bssid
        if not bssid:
            self.notify("Selecciona una fila de la tabla de APs.", severity="warning")
            return
        self.set_target(bssid)

    # ================================================================= Captura
    @on(Button.Pressed, "#btn-cap-start")
    def _on_cap_start(self) -> None:
        if not self._require_root() or not self._require_monitor() or not self._require_target():
            return
        if "capture" in self.app.procs:
            self.notify("Ya hay una captura en curso.", severity="warning")
            return
        st = self.app.state
        ch = self.query_one("#cap-channel", Input).value.strip() or st.target_channel
        prefix = st.session_dir / "capture"
        argv = attacks.capture_argv(st.monitor_iface, prefix,
                                    bssid=st.target_bssid, channel=ch)
        log = st.session_dir / "capture.stdout.log"
        try:
            proc = ManagedProcess(argv, log_file=log).start()
        except CommandError as exc:
            self.notify(str(exc), severity="error")
            return
        self.app.procs["capture"] = proc
        self.app.log_line(f"[captura] {' '.join(argv)}")
        self.app.log_event(f"Captura iniciada sobre {st.target_bssid} (canal {ch or '-'})")
        self.query_one("#cap-status", Static).update("Capturando ... buscando handshake")
        self._cap_loop(proc, prefix, log)

    @work(thread=True)
    def _cap_loop(self, proc: ManagedProcess, prefix: Path, log: Path) -> None:
        worker = get_current_worker()
        handshake = False
        try:
            while not worker.is_cancelled and proc.poll() is None:
                time.sleep(1.5)
                try:
                    content = log.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    content = ""
                if not handshake and ("WPA handshake:" in content
                                      or "handshake(s) captured" in content):
                    handshake = True
                    self.app.call_from_thread(self._on_handshake, prefix)
        finally:
            proc.stop()
            self.app.call_from_thread(self._cap_finished, handshake)

    def _on_handshake(self, prefix: Path) -> None:
        self.app.state.events.append(f"{now_iso()}  Handshake capturado ({prefix.name})")
        cap = prefix.parent / (prefix.name + "-01.cap")
        self.app.log_line(f"[handshake] capturado. Fichero: {cap}")
        self.notify("Handshake capturado.", severity="information")
        self.refresh_captures()

    def _cap_finished(self, handshake: bool) -> None:
        self.app.procs.pop("capture", None)
        if not handshake:
            self.query_one("#cap-status", Static).update(
                "Captura detenida sin handshake. Prueba a lanzar un deauth "
                "mientras capturas."
            )
        else:
            self.query_one("#cap-status", Static).update("Captura detenida. Handshake disponible.")
        self.app.log_event("Captura detenida")
        self.refresh_captures()

    @on(Button.Pressed, "#btn-cap-stop")
    def _on_cap_stop(self) -> None:
        self._kill_process("capture")

    # ================================================================= Ataques
    @on(Button.Pressed, "#btn-deauth-here")
    def _on_deauth_here(self) -> None:
        if not self._require_target():
            return
        count = self._atk_count()
        self._run_deauth(self.app.state.target_bssid, self._atk_client(), count)

    @on(Button.Pressed, "#btn-deauth")
    def _on_deauth(self) -> None:
        if not self._require_root() or not self._require_monitor() or not self._require_target():
            return
        self._run_deauth(
            self.app.state.target_bssid,
            self._atk_client(),
            self._atk_count(),
        )

    def _run_deauth(self, bssid: str | None, client: str | None, count: int) -> None:
        if not self._require_root() or not self._require_monitor() or not bssid:
            return
        argv = attacks.deauth_argv(self.app.state.monitor_iface, bssid, client, count)
        self.app.log_event(f"Deauth x{count} -> {bssid}" + (f" (cliente {client})" if client else ""))
        self._run_attack(argv, "atk-log")

    @on(Button.Pressed, "#btn-fakeauth")
    def _on_fakeauth(self) -> None:
        if not self._require_root() or not self._require_monitor() or not self._require_target():
            return
        st = self.app.state
        ap = st.aps.get(st.target_bssid) if st.target_bssid else None
        essid = ap.display_essid if ap and ap.essid else None
        argv = attacks.fakeauth_argv(st.monitor_iface, st.target_bssid, essid)
        self.app.log_event(f"Fake auth -> {st.target_bssid}")
        self._run_attack(argv, "atk-log")

    @on(Button.Pressed, "#btn-arp")
    def _on_arp(self) -> None:
        if not self._require_root() or not self._require_monitor() or not self._require_target():
            return
        st = self.app.state
        source = interface.interface_mac(st.monitor_iface or "") or ""
        if not source:
            self.notify("No se pudo leer la MAC de la interfaz.", severity="error")
            return
        argv = attacks.arpreplay_argv(st.monitor_iface, st.target_bssid, source)
        self.app.log_event(f"ARP replay -> {st.target_bssid}")
        self._run_attack(argv, "atk-log")

    @work(thread=True)
    def _run_attack(self, argv: list[str], log_widget_id: str) -> None:
        try:
            proc = ManagedProcess(argv).start()
        except CommandError as exc:
            self.app.call_from_thread(self.notify, str(exc), severity="error")
            return
        self.app.call_from_thread(self.app.log_line, f"[ataque] {' '.join(argv)}")
        for line in proc.lines():
            if line.strip():
                self.app.call_from_thread(self._write_log, log_widget_id, line)
        proc.wait()
        self.app.call_from_thread(self._write_log, log_widget_id, "--- fin ---")

    def _atk_client(self) -> str | None:
        val = self.query_one("#atk-client", Input).value.strip()
        return val or None

    def _atk_count(self) -> int:
        raw = self.query_one("#atk-count", Input).value.strip()
        return int(raw) if raw.isdigit() else 5

    # ================================================================ Cracking
    @on(Button.Pressed, "#btn-refresh-caps")
    def _on_refresh_caps(self) -> None:
        self.refresh_captures()

    @on(Button.Pressed, "#btn-crack-start")
    def _on_crack_start(self) -> None:
        st = self.app.state
        sel = self.query_one("#capfile-select", Select).value
        if sel is Select.BLANK or sel is None:
            self.notify("Selecciona una captura (.cap).", severity="error")
            return
        wl = self.query_one("#wordlist", Input).value.strip()
        if not wl:
            self.notify("Indica un fichero de diccionario.", severity="error")
            return
        if not Path(wl).is_file():
            self.notify(f"No existe el diccionario: {wl}", severity="error")
            return
        if "crack" in self.app.procs:
            self.notify("Ya hay un cracking en curso.", severity="warning")
            return
        capfile = str(sel)
        argv = cracker.build_aircrack_argv(
            Path(capfile), wordlist=Path(wl), bssid=st.target_bssid
        )
        try:
            proc = ManagedProcess(argv).start()
        except CommandError as exc:
            self.notify(str(exc), severity="error")
            return
        self.app.procs["crack"] = proc
        self.app.log_line(f"[crack] {' '.join(argv)}")
        self.app.log_event(f"Cracking iniciado sobre {Path(capfile).name}")
        self.query_one("#crack-status", Static).update("Iniciando aircrack-ng ...")
        self._crack_loop(proc, capfile)

    @work(thread=True)
    def _crack_loop(self, proc: ManagedProcess, capfile: str) -> None:
        worker = get_current_worker()
        key: str | None = None
        last = 0.0
        for line in proc.lines():
            if worker.is_cancelled:
                break
            found = cracker.parse_key_found(line)
            if found:
                key = found
                break
            now = time.time()
            if line.strip() and now - last > 0.4:
                last = now
                self.app.call_from_thread(self._write_log, "crack-status", line.strip())
        proc.wait()
        self.app.call_from_thread(self._crack_finished, capfile, key)

    def _crack_finished(self, capfile: str, key: str | None) -> None:
        self.app.procs.pop("crack", None)
        st = self.app.state
        status = "CLAVE ENCONTRADA" if key else "sin exito"
        st.cracks.append({
            "capfile": Path(capfile).name,
            "bssid": st.target_bssid or "",
            "status": status,
            "key": key or "",
            "timestamp": now_iso(),
        })
        if key:
            msg = f"[green]CLAVE ENCONTRADA: {key}[/green]"
            self.query_one("#crack-status", Static).update(msg)
            self.app.log_line(f"[crack] CLAVE ENCONTRADA: {key}")
            self.app.log_event(f"Clave recuperada para {st.target_bssid}: {key}")
            self.notify(f"Clave encontrada: {key}", severity="information")
        else:
            self.query_one("#crack-status", Static).update(
                "Sin exito (handshake incompleto o clave fuera del diccionario)."
            )
            self.app.log_event("Cracking finalizado sin exito")
            self.notify("No se encontro la clave.", severity="warning")

    @on(Button.Pressed, "#btn-crack-stop")
    def _on_crack_stop(self) -> None:
        self._kill_process("crack")

    # ================================================================ AP falso
    @on(Button.Pressed, "#btn-ap-start")
    def _on_ap_start(self) -> None:
        if not self._require_root() or not self._require_monitor():
            return
        if "fakeap" in self.app.procs:
            self.notify("El AP falso ya esta en ejecucion.", severity="warning")
            return
        essid = self.query_one("#ap-essid", Input).value.strip()
        if not essid:
            self.notify("Indica un ESSID.", severity="error")
            return
        ch = self.query_one("#ap-channel", Input).value.strip()
        channel = int(ch) if ch.isdigit() else None
        argv = attacks.airbase_argv(self.app.state.monitor_iface, essid, channel)
        try:
            proc = ManagedProcess(argv).start()
        except CommandError as exc:
            self.notify(str(exc), severity="error")
            return
        self.app.procs["fakeap"] = proc
        self.app.log_line(f"[airbase] {' '.join(argv)}")
        self.app.log_event(f"AP falso levantado: {essid} (canal {channel or '-'})")
        self._fakeap_loop(proc)

    @work(thread=True)
    def _fakeap_loop(self, proc: ManagedProcess) -> None:
        for line in proc.lines():
            if line.strip():
                self.app.call_from_thread(self._write_log, "ap-log", line)
        proc.wait()
        self.app.call_from_thread(self._write_log, "ap-log", "--- AP detenido ---")

    @on(Button.Pressed, "#btn-ap-stop")
    def _on_ap_stop(self) -> None:
        self._kill_process("fakeap")

    # ================================================================= Informe
    @on(Button.Pressed, "#btn-report")
    def _on_report(self) -> None:
        st = self.app.state
        meta = {
            "session_dir": str(st.session_dir),
            "iface": st.iface,
            "monitor_iface": st.monitor_iface,
            "authorized": "si" if st.authorized else "no",
            "auth_timestamp": st.auth_timestamp,
        }
        try:
            md_path, html_path = write_report(
                st.session_dir, meta, st.aps, st.clients, st.cracks, st.attacks,
                st.events, ai_analysis=st.ai_analysis or None,
            )
        except Exception as exc:  # noqa: BLE001
            self.notify(f"Error generando informe: {exc}", severity="error")
            return
        self.query_one("#report-status", Static).update(
            f"Informe generado:\n  {md_path}\n  {html_path}"
        )
        try:
            preview = md_path.read_text(encoding="utf-8")[:1500]
        except OSError:
            preview = ""
        self.query_one("#report-preview", Static).update(preview)
        self.app.log_event(f"Informe generado: {md_path.name}")
        self.notify("Informe generado.")

    # ================================================================= Auto + IA
    def _int_input(self, widget_id: str, default: int) -> int:
        raw = self.query_one(f"#{widget_id}", Input).value.strip()
        return int(raw) if raw.isdigit() else default

    def _auto_log(self, text: str) -> None:
        self._write_log("auto-log", text)

    def trigger_auto(self) -> None:
        """Punto de entrada para el atajo de teclado (F9)."""
        self._on_auto_start()

    @on(Button.Pressed, "#btn-auto-start")
    def _on_auto_start(self) -> None:
        if not self._require_root():
            return
        if not self.app.state.authorized:
            self.notify("Falta la confirmacion de autorizacion.", severity="error")
            return
        if self.app.state.auto_running:
            self.notify("Ya hay una auditoria automatica en curso.",
                        severity="warning")
            return

        st = self.app.state
        wordlist = self.query_one("#auto-wordlist", Input).value.strip() or None
        use_ai = self.query_one("#auto-use-ai", Switch).value
        scan_seconds = self._int_input("auto-scan-secs", 30)
        capture_seconds = self._int_input("auto-cap-secs", 60)

        st.auto_running = True
        self._auto_stop_requested = False
        self.query_one("#auto-status", Static).update(
            "Auditoria automatica en curso ...")
        self._auto_log("[auto] iniciando flujo automatico completo")

        self._auto_auditor = AutoAuditor(
            st.session_dir,
            iface=st.iface,
            monitor_iface=st.monitor_iface,
            target_bssid=st.target_bssid,
            wordlist=wordlist,
            scan_seconds=scan_seconds,
            capture_seconds=capture_seconds,
            use_ai=use_ai,
            on_log=lambda m: self.app.call_from_thread(self._auto_log, m),
            on_event=lambda m: self.app.call_from_thread(self.app.log_event, m),
            should_stop=lambda: self._auto_stop_requested,
        )
        self._auto_worker(self._auto_auditor)

    @work(thread=True)
    def _auto_worker(self, auditor: AutoAuditor) -> None:
        try:
            result = auditor.run()
        except Exception as exc:  # noqa: BLE001
            result = {"error": str(exc), "aborted": True}
        self.app.call_from_thread(self._auto_finished, result)

    def _auto_finished(self, result: dict) -> None:
        st = self.app.state
        st.auto_running = False
        st.auto_result = result
        st.ai_analysis = result.get("ai_analysis", "") or ""
        self._auto_auditor = None

        # Refleja la interfaz usada y refresca tablas/capturas.
        st.iface = result.get("interfaz") or st.iface
        if st.monitor_iface and not interface.is_monitor(st.monitor_iface):
            st.monitor_iface = None
        self.refresh_captures()
        self.refresh_monitor_status()
        self.update_env()

        key = result.get("key") or ""
        status = result.get("outcome") or result.get("error") or "-"
        if key:
            st.cracks.append({
                "capfile": "auto",
                "bssid": (result.get("target") or {}).get("bssid", ""),
                "status": "CLAVE ENCONTRADA",
                "key": key,
                "timestamp": now_iso(),
            })
            summary = f"Completado. Resultado: {status}. CLAVE: {key}"
        else:
            summary = f"Completado. Resultado: {status}."
        summary += " Pulsa 'Generar informe' para el informe con analisis IA."

        self.query_one("#auto-status", Static).update(summary)
        self._auto_log(f"[auto] fin del flujo: {status}")
        if result.get("ai_analysis"):
            self._auto_log("[ia] " + result["ai_analysis"])
        self.notify(("Clave encontrada: " + key) if key else "Flujo automatico fin.",
                    severity="information" if key else "warning")

    @on(Button.Pressed, "#btn-auto-stop")
    def _on_auto_stop(self) -> None:
        self._auto_stop_requested = True
        if self._auto_auditor:
            self._auto_auditor.stop()
        self.notify("Solicitada parada del flujo automatico.", severity="warning")

    @on(Button.Pressed, "#btn-auto-report")
    def _on_auto_report(self) -> None:
        self._on_report()

    # ================================================================= utils
    def _kill_process(self, name: str) -> None:
        proc = self.app.procs.pop(name, None)
        if proc:
            proc.stop()

    def _write_log(self, widget_id: str, line: str) -> None:
        if widget_id == "crack-status":
            try:
                self.query_one("#crack-status", Static).update(line)
            except Exception:
                pass
            return
        try:
            widget = self.query_one(f"#{widget_id}", RichLog)
            widget.write(line)
        except Exception:
            pass
