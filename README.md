# WiFi Audit TUI

Interfaz de terminal (TUI) construida con [Textual](https://textual.textualize.io/)
que envuelve la **suite aircrack-ng** para realizar auditorías Wi-Fi
**autorizadas** sin tener que memorizar decenas de comandos y flags.

> ⚠️ **Uso legal.** Esta herramienta ejecuta operaciones **activas** contra
> redes inalámbricas (desautenticación, inyección, AP falso, cracking). Úsala
> **solo** sobre redes de tu propiedad o para las que tengas **autorización
> escrita**. El uso no autorizado es delito en la mayoría de países. La
> aplicación exige una confirmación explícita al arrancar y la deja registrada
> en el informe.

---

## Características

| Pestaña | Qué hace | Herramienta de fondo |
|---|---|---|
| **1 Interfaz** | Detecta adaptadores, activa/desactiva modo monitor, `check kill` | `airmon-ng` |
| **2 Escaneo** | Descubre APs y clientes en vivo en una tabla interactiva | `airodump-ng` (CSV) |
| **3 Captura** | Captura dirigida a un AP y detecta el handshake | `airodump-ng` (+ pcap) |
| **4 Ataques** | Deauth, fake auth, ARP replay | `aireplay-ng` |
| **5 Cracking** | Prueba el handshake contra un diccionario, progreso en vivo | `aircrack-ng` |
| **6 AP falso** | Levanta un punto de acceso falso | `airbase-ng` |
| **7 Informe** | Genera informe Markdown + HTML de la sesión | — |
| **8 Registro** | Salida cruda de todas las herramientas | — |

- Escaneo en vivo parseando el **CSV** de `airodump-ng` (más robusto que
  interpretar la salida curses).
- Todo el trabajo de cada sesión se guarda en `~/wifi-audit-sessions/session-<fecha>/`.
- Cierre ordenado: al salir se terminan los procesos de la suite.

---

## Requisitos

- **Linux nativo** (Kali, Parrot, Ubuntu…). El modo monitor e inyección
  necesitan acceso directo al hardware de red; **no funcionan en WSL**.
- Python **3.10+**.
- La **suite aircrack-ng** instalada:
  ```bash
  sudo apt update && sudo apt install aircrack-ng
  ```
- Una tarjeta Wi-Fi que soporte **modo monitor** e **inyección**
  (Atheros AR9271, Ralink RT3070, Realtek RTL8812AU, Alfa…).
- **root** para operar.

---

## Instalación

```bash
cd wifi-audit-tui
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

o, sin instalar como paquete:

```bash
pip install -r requirements.txt
```

## Ejecución

```bash
sudo ./run.sh
# o
sudo python3 -m wifi_audit
```

El lanzador te pide root si no lo eres.

---

## Flujo de trabajo típico

1. **Interfaz**: pulsa *Refrescar*, elige tu adaptador y *Iniciar monitor*.
   Si algo bloquea el adaptador, usa antes *check kill*.
2. **Escaneo**: *Iniciar escaneo*. Aparecen los APs en la tabla. Selecciona la
   fila del objetivo y pulsa *Fijar AP seleccionado como objetivo* (o Enter).
3. **Captura**: *Iniciar captura* en el canal del AP. Mientras captura, lanza
   *Deauth* para forzar la reconexión de un cliente y atrapar el handshake.
   La barra de estado avisa cuando el handshake se detecta.
4. **Cracking**: elige el `.cap` de la sesión, indica un diccionario
   (p. ej. `/usr/share/wordlists/rockyou.txt`) e *Iniciar cracking*.
5. **Informe**: *Generar informe* → `report.md` y `report.html` en la carpeta
   de la sesión.

---

## Estructura del proyecto

```
wifi-audit-tui/
├── pyproject.toml
├── requirements.txt
├── run.sh
└── wifi_audit/
    ├── app.py                # App de Textual + estado global
    ├── app.tcss              # estilos
    ├── auth.py               # aviso legal / frase de autorización
    ├── config.py             # rutas, detección de root
    ├── state.py              # estado de la sesión
    ├── core/
    │   ├── runner.py         # subprocess con streaming y parada por grupo
    │   ├── tools.py          # detección de la suite
    │   ├── interface.py      # airmon-ng: modo monitor
    │   ├── scanner.py        # parser del CSV de airodump-ng
    │   ├── cracker.py        # aircrack-ng
    │   ├── attacks.py        # aireplay-ng / airbase-ng
    │   └── report.py         # informes Markdown + HTML
    └── screens/
        ├── authorization.py  # modal de autorización
        └── main.py           # pantalla principal con las pestañas
```

La lógica de la suite vive **solo** en `wifi_audit/core/`; la UI no construye
comandos a mano salvo para mostrarlos, lo que facilita testear el núcleo o
reutilizarlo (por ejemplo en una CLI o una API).

---

## VM con USB passthrough (VirtualBox / VMware)

Si ejecutas Kali en una máquina virtual:

1. Con la VM apagada, añade un **filtro USB** para tu adaptador
   (Configuración → USB → añadir dispositivo).
2. Arranca la VM y comprueba con `lsusb` que el adaptador aparece.
3. Verifica la interfaz con `iw dev`. Debe verse como `wlan0`, `wlan1`, etc.
4. Si el adaptador es inestable, usa un **hub USB alimentado**; los adaptadores
   de alta potencia pueden consumir más de lo que da el puerto.

---

## Limitaciones y notas

- **WPA3 (SAE)** no es crackeable con este flujo; el handshake WPA3 no se puede
  atacar con diccionario igual que WPA2.
- **PMKID**: `aircrack-ng` 1.6+ lo detecta automáticamente; la captura debe
  contener el PMKID.
- El modo monitor/inyección depende por completo del **driver**; algunos
  adaptadores no soportan inyección.
- El escaneo se refresca cada segundo; con cientos de APs la tabla puede
  actualizarse algo despacio (normal).

---

## Licencia

MIT. El autor no se hace responsable del uso indebido de la herramienta.
