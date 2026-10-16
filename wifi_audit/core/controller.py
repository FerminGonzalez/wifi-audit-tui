"""Controlador de sesion independiente de la interfaz.

Encapsula las operaciones sobre la suite aircrack-ng (interfaz/monitor,
escaneo, captura, ataques, cracking, AP falso e informe) sin depender de
Textual ni de ningun framework web. Lo consumen la app web y, en el futuro,
puede sustituir la logica de la TUI.

Mantiene:
  * el estado de la sesion (:class:`~wifi_audit.state.AppState`)
  * los procesos en curso en un diccionario
  * un buffer circular de lineas de registro
"""

from __future__ import annotations

import threading
import time
from collections import deque
from pathlib import Path

from ..config import is_root, now_iso
from ..state import AppState
from . import attacks, cracker, interface, scanner
from .report import write_report
from .runner import CommandError, ManagedProcess
from .tools import detect_tools, missing_tools

CRACK_PHRASE = "AUTORIZADO"


class SessionController:
    def __init__(self, state: AppState, log_size: int = 500):
        self.state = state
        self.procs: dict[str, ManagedProcess] = {}
        self.logs: deque[str] = deque(maxlen=log_size)
        self._lock = threading.RLock()
        self._threads: list[threading.Thread] = []

    # ------------------------------------------------------------- utilidad
    def log(self, text: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        with self._lock:
            self.logs.append(f"{stamp}  {text}")

    def log_event(self, text: str) -> None:
        with self._lock:
            self.state.events.append(f"{now_iso()}  {text}")
        self.log(f"* {text}")

    def _spawn(self, target, *args) -> None:
        thread = threading.Thread(target=target, args=args, daemon=True)
        thread.start()
        self._threads.append(thread)

    # ------------------------------------------------------- autorizacion
    def authorize(self, phrase: str) -> tuple[bool, str]:
        if phrase.strip().upper() != CRACK_PHRASE:
            return False, "Frase incorrecta"
        self.state.authorized = True
        self.state.auth_timestamp = now_iso()
        self.log_event("Autorizacion confirmada por el operador")
        return True, "Autorizacion registrada"

    # ------------------------------------------------------------ interfaz
    def list_wireless(self) -> list[str]:
        return interface.list_wireless_interfaces()

    def check_kill(self) -> tuple[bool, str]:
        if not is_root():
            return False, "Se requieren privilegios de root"
        try:
            out = interface.check_kill()
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)
        self.log("[check kill] " + out.strip())
        return True, "Procesos interferentes terminados"

    def start_monitor(self, iface: str) -> tuple[bool, str]:
        if not is_root():
            return False, "Se requieren privilegios de root"
        if not iface:
            return False, "Interfaz no indicada"
        self.log(f"[monitor] activando modo monitor en {iface} ...")
        try:
            mon = interface.start_monitor(iface)
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)
        if not mon:
            return False, "No se pudo activar el modo monitor"
        self.state.iface = iface
        self.state.monitor_iface = mon
        self.log_event(f"Modo monitor activado: {iface} -> {mon}")
        return True, mon

    def stop_monitor(self) -> tuple[bool, str]:
        mon = self.state.monitor_iface
        if not mon:
            return False, "No hay monitor activo"
        self.stop("scan")
        self.stop("capture")
        try:
            interface.stop_monitor(mon)
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)
        self.state.monitor_iface = None
        self.log_event(f"Modo monitor desactivado: {mon}")
        return True, "Monitor desactivado"

    # -------------------------------------------------------------- escaneo
    def start_scan(self, channel: str | None = None, bssid: str | None = None) -> tuple[bool, str]:
        if not is_root():
            return False, "Se requieren privilegios de root"
        if not self.state.monitor_iface:
            return False, "No hay interfaz en modo monitor"
        with self._lock:
            if "scan" in self.procs:
                return False, "Ya hay un escaneo en curso"
            prefix = self.state.session_dir / "scan"
            argv = attacks.scan_argv(self.state.monitor_iface, prefix, channel, bssid)
            log_file = self.state.session_dir / "scan.stdout.log"
            try:
                proc = ManagedProcess(argv, log_file=log_file).start()
            except CommandError as exc:
                return False, str(exc)
            self.procs["scan"] = proc
        self.log(f"[scan] {' '.join(argv)}")
        self.log_event("Escaneo iniciado")
        self._spawn(self._scan_loop, proc, prefix)
        return True, "Escaneo iniciado"

    def _scan_loop(self, proc: ManagedProcess, prefix: Path) -> None:
        try:
            while proc.running():
                time.sleep(1.0)
                csv_path = scanner.latest_csv(prefix)
                if csv_path:
                    aps, clients = scanner.parse_airodump_csv(csv_path)
                    with self._lock:
                        self.state.aps = aps
                        self.state.clients = clients
        finally:
            proc.stop()
            with self._lock:
                self.procs.pop("scan", None)
            self.log("[scan] detenido")

    # -------------------------------------------------------------- captura
    def set_target(self, bssid: str) -> tuple[bool, str]:
        ap = self.state.aps.get(bssid)
        if not ap:
            return False, "AP no encontrado"
        self.state.target_bssid = bssid
        self.state.target_channel = ap.channel
        self.log_event(f"Objetivo fijado: {ap.display_essid} ({bssid}) canal {ap.channel}")
        return True, "Objetivo fijado"

    def start_capture(self, channel: str | None = None) -> tuple[bool, str]:
        if not is_root():
            return False, "Se requieren privilegios de root"
        if not self.state.monitor_iface:
            return False, "No hay interfaz en modo monitor"
        if not self.state.target_bssid:
            return False, "Fija un AP objetivo primero"
        with self._lock:
            if "capture" in self.procs:
                return False, "Ya hay una captura en curso"
            ch = (channel or self.state.target_channel or "").strip() or None
            prefix = self.state.session_dir / "capture"
            argv = attacks.capture_argv(
                self.state.monitor_iface, prefix, bssid=self.state.target_bssid, channel=ch
            )
            log_file = self.state.session_dir / "capture.stdout.log"
            try:
                proc = ManagedProcess(argv, log_file=log_file).start()
            except CommandError as exc:
                return False, str(exc)
            self.procs["capture"] = proc
        self.log(f"[captura] {' '.join(argv)}")
        self.log_event(f"Captura iniciada sobre {self.state.target_bssid} (canal {ch or '-'})")
        self._spawn(self._capture_loop, proc, prefix, log_file)
        return True, "Captura iniciada"

    def _capture_loop(self, proc: ManagedProcess, prefix: Path, log_file: Path) -> None:
        handshake = False
        try:
            while proc.running():
                time.sleep(1.5)
                try:
                    content = log_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    content = ""
                if not handshake and ("WPA handshake:" in content
                                      or "handshake(s) captured" in content):
                    handshake = True
                    self.log_event(f"Handshake capturado ({prefix.name}-01.cap)")
        finally:
            proc.stop()
            with self._lock:
                self.procs.pop("capture", None)
            self.log("[captura] detenida" + ("" if handshake else " (sin handshake)"))

    # --------------------------------------------------------------- ataques
    def deauth(self, client: str | None = None, count: int = 10) -> tuple[bool, str]:
        if not is_root():
            return False, "Se requieren privilegios de root"
        if not self.state.monitor_iface:
            return False, "No hay interfaz en modo monitor"
        if not self.state.target_bssid:
            return False, "Fija un AP objetivo primero"
        argv = attacks.deauth_argv(
            self.state.monitor_iface, self.state.target_bssid, client or None, count
        )
        self.log_event(f"Deauth x{count} -> {self.state.target_bssid}"
                       + (f" (cliente {client})" if client else ""))
        return self._run_streaming("attack", argv)

    def fakeauth(self) -> tuple[bool, str]:
        if not is_root() or not self.state.monitor_iface or not self.state.target_bssid:
            return False, "Revisa root, monitor y objetivo"
        ap = self.state.aps.get(self.state.target_bssid)
        essid = ap.display_essid if ap and ap.essid else None
        argv = attacks.fakeauth_argv(self.state.monitor_iface, self.state.target_bssid, essid)
        self.log_event(f"Fake auth -> {self.state.target_bssid}")
        return self._run_streaming("attack", argv)

    def arpreplay(self) -> tuple[bool, str]:
        if not is_root() or not self.state.monitor_iface or not self.state.target_bssid:
            return False, "Revisa root, monitor y objetivo"
        source = interface.interface_mac(self.state.monitor_iface) or ""
        if not source:
            return False, "No se pudo leer la MAC de la interfaz"
        argv = attacks.arpreplay_argv(self.state.monitor_iface, self.state.target_bssid, source)
        self.log_event(f"ARP replay -> {self.state.target_bssid}")
        return self._run_streaming("attack", argv)

    def _run_streaming(self, key: str, argv: list[str]) -> tuple[bool, str]:
        try:
            proc = ManagedProcess(argv).start()
        except CommandError as exc:
            return False, str(exc)
        self.log(f"[ataque] {' '.join(argv)}")
        self._spawn(self._stream_loop, proc, key)
        return True, "Ejecutando"

    def _stream_loop(self, proc: ManagedProcess, key: str) -> None:
        with self._lock:
            self.procs[key] = proc
        try:
            for line in proc.lines():
                if line.strip():
                    self.log(line.strip())
        finally:
            proc.wait()
            with self._lock:
                self.procs.pop(key, None)
            self.log("--- fin ---")

    # ------------------------------------------------------------- cracking
    def start_crack(self, capfile: str, wordlist: str) -> tuple[bool, str]:
        if not Path(capfile).is_file():
            return False, "El fichero de captura no existe"
        if not Path(wordlist).is_file():
            return False, "El diccionario no existe"
        with self._lock:
            if "crack" in self.procs:
                return False, "Ya hay un cracking en curso"
            argv = cracker.build_aircrack_argv(
                Path(capfile), wordlist=Path(wordlist), bssid=self.state.target_bssid
            )
            try:
                proc = ManagedProcess(argv).start()
            except CommandError as exc:
                return False, str(exc)
            self.procs["crack"] = proc
        self.log(f"[crack] {' '.join(argv)}")
        self.log_event(f"Cracking iniciado sobre {Path(capfile).name}")
        self._spawn(self._crack_loop, proc, capfile)
        return True, "Cracking iniciado"

    def _crack_loop(self, proc: ManagedProcess, capfile: str) -> None:
        key: str | None = None
        last = 0.0
        for line in proc.lines():
            found = cracker.parse_key_found(line)
            if found:
                key = found
                break
            now = time.time()
            if line.strip() and now - last > 0.4:
                last = now
                self.log(line.strip())
        proc.wait()
        with self._lock:
            self.procs.pop("crack", None)
            self.state.cracks.append({
                "capfile": Path(capfile).name,
                "bssid": self.state.target_bssid or "",
                "status": "CLAVE ENCONTRADA" if key else "sin exito",
                "key": key or "",
                "timestamp": now_iso(),
            })
        if key:
            self.log_event(f"Clave recuperada para {self.state.target_bssid}: {key}")
        else:
            self.log_event("Cracking finalizado sin exito")

    # -------------------------------------------------------------- AP falso
    def start_fakeap(self, essid: str, channel: int | None = None) -> tuple[bool, str]:
        if not is_root():
            return False, "Se requieren privilegios de root"
        if not self.state.monitor_iface:
            return False, "No hay interfaz en modo monitor"
        if not essid.strip():
            return False, "Indica un ESSID"
        with self._lock:
            if "fakeap" in self.procs:
                return False, "El AP falso ya esta en ejecucion"
            argv = attacks.airbase_argv(self.state.monitor_iface, essid, channel)
            try:
                proc = ManagedProcess(argv).start()
            except CommandError as exc:
                return False, str(exc)
            self.procs["fakeap"] = proc
        self.log(f"[airbase] {' '.join(argv)}")
        self.log_event(f"AP falso levantado: {essid} (canal {channel or '-'})")
        self._spawn(self._fakeap_loop, proc)
        return True, "AP falso en ejecucion"

    def _fakeap_loop(self, proc: ManagedProcess) -> None:
        try:
            for line in proc.lines():
                if line.strip():
                    self.log(line.strip())
        finally:
            proc.wait()
            with self._lock:
                self.procs.pop("fakeap", None)
            self.log("--- AP detenido ---")

    # ---------------------------------------------------------------- informe
    def generate_report(self) -> tuple[bool, dict]:
        st = self.state
        meta = {
            "session_dir": str(st.session_dir),
            "iface": st.iface,
            "monitor_iface": st.monitor_iface,
            "authorized": "si" if st.authorized else "no",
            "auth_timestamp": st.auth_timestamp,
        }
        try:
            md_path, html_path = write_report(
                st.session_dir, meta, st.aps, st.clients, st.cracks, st.attacks, st.events
            )
        except Exception as exc:  # noqa: BLE001
            return False, {"error": str(exc)}
        self.log_event(f"Informe generado: {md_path.name}")
        return True, {"markdown": str(md_path), "html": str(html_path)}

    # ----------------------------------------------------------------- utils
    def stop(self, key: str) -> None:
        with self._lock:
            proc = self.procs.pop(key, None)
        if proc:
            proc.stop()

    def shutdown(self) -> None:
        with self._lock:
            procs = list(self.procs.values())
            self.procs.clear()
        for proc in procs:
            try:
                proc.stop()
            except Exception:
                pass

    # -------------------------------------------------------------- snapshot
    def snapshot(self) -> dict:
        st = self.state
        running = {k: p.running() for k, p in self.procs.items()}
        target_ap = st.aps.get(st.target_bssid) if st.target_bssid else None
        return {
            "env": {
                "root": is_root(),
                "missing_tools": missing_tools(),
                "tools": {n: bool(s.available) for n, s in detect_tools().items()},
                "wireless_ifaces": interface.list_wireless_interfaces(),
                "iface": st.iface,
                "monitor_iface": st.monitor_iface,
                "session_dir": str(st.session_dir),
                "authorized": st.authorized,
                "auth_timestamp": st.auth_timestamp,
            },
            "target": {
                "bssid": st.target_bssid,
                "channel": st.target_channel,
                "essid": target_ap.display_essid if target_ap else None,
            },
            "aps": [
                {
                    "bssid": ap.bssid,
                    "essid": ap.display_essid,
                    "channel": ap.channel,
                    "encryption": ap.encryption,
                    "cipher": ap.cipher,
                    "auth": ap.auth,
                    "power": ap.power,
                    "beacons": ap.beacons,
                    "data": ap.data,
                    "clients": len(ap.clients),
                }
                for ap in st.aps.values()
            ],
            "clients": [
                {
                    "mac": c.mac,
                    "bssid": c.bssid,
                    "power": c.power,
                    "packets": c.packets,
                    "probed": c.probed,
                }
                for c in st.clients.values()
            ],
            "captures": [p.name for p in scanner.list_capture_files(st.session_dir)],
            "cracks": st.cracks,
            "running": running,
            "logs": list(self.logs)[-200:],
            "events": st.events[-50:],
        }
