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
| **9 Auto + IA** | Auditoría automática completa decidida por IA | suite + IA |

- **Modo automático (pestaña 9 o tecla F9)**: un solo botón ejecuta todo el
  flujo —comprobación de entorno, `check kill`, modo monitor, escaneo, elección
  de objetivo, captura, ataque activo si hace falta, cracking y análisis— sin
  intervención.
- **Elección de método según el caso** con tabla determinista (siempre como
  respaldo) y, si hay IA configurada, recomendación validada contra una lista
  de enfoques permitidos. Ver más abajo.
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

### Instalación rápida (recomendada)

Con el instalador de una línea (instala dependencias, clona y deja el launcher):

```bash
curl -sSL https://raw.githubusercontent.com/FerminGonzalez/wifi-audit-tui/main/install.sh | sudo bash
```

O con el paquete **`.deb`** (Kali/Debian), que resuelve las dependencias vía `apt`:

```bash
./packaging/build-deb.sh                                   # genera dist/wifi-audit-tui_1.0.0_all.deb
sudo apt install ./dist/wifi-audit-tui_1.0.0_all.deb       # instala con dependencias
wifi-audit-tui                                             # lanzar
```

### Instalación manual (desarrollo)

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

### Diagnóstico

Comprueba el entorno (Python, dependencias, suite aircrack-ng, adaptador y
modo monitor) sin abrir la TUI:

```bash
sudo python3 -m wifi_audit --check
# opcional: omitir la prueba de modo monitor
sudo python3 -m wifi_audit --check --no-monitor
```

El diagnóstico reconoce adaptadores USB conocidos e informa si el chipset
soporta modo monitor real (p. ej. marca el MediaTek MT7921U como *limitado*).

### Launcher de escritorio

El repositorio incluye un acceso directo con icono en `assets/`:

```bash
mkdir -p ~/.local/share/applications
cp assets/wifi-audit-tui.desktop ~/.local/share/applications/
cp assets/wifi-audit-tui.desktop ~/Escritorio 2>/dev/null || cp assets/wifi-audit-tui.desktop ~/Desktop
chmod +x ~/.local/share/applications/wifi-audit-tui.desktop
```

> El `.desktop` usa rutas absolutas de `~/wifi-audit-tui`; edítalo si instalas
> el proyecto en otra ruta.

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

## Auditoría automática e IA

La pestaña **9 Auto + IA** (o la tecla **F9**) ejecuta el flujo completo sin
intervención: prepara la interfaz, escanea, elige objetivo, decide el método,
captura, ataca si hace falta, crackea, interpreta los resultados y los deja
listos para el informe. Todo queda registrado en la cronología de la sesión.

### Elección del método (según el caso)

| AP detectado | Enfoque automático |
|---|---|
| WEP | `fakeauth` + `arpreplay` (generar IVs) y cracking sin diccionario |
| WPA/WPA2 con clientes | captura + `deauth` dirigido → handshake 4 vías |
| WPA/WPA2 sin clientes | PMKID (client-less) primero |
| WPA3 / SAE | no atacable por diccionario → se documenta |
| Red abierta | se documenta como hallazgo |

Si hay IA configurada, propone el enfoque y una justificación; la respuesta se
**valida contra una lista de enfoques permitidos** y, ante cualquier duda,
falla, o si no hay IA, se usa la tabla determinista de arriba. La IA nunca es
la única barrera: la autorización del arranque sigue siendo obligatoria.

### Configuración de la IA (opcional)

La capa de IA es agnóstica: funciona con **Ollama local** o con cualquier
**API compatible con OpenAI** (DeepSeek, OpenAI, Groq...). Se controla por
variables de entorno —no hay dependencias nuevas, usa `urllib`:

| Variable | Descripción | Por defecto |
|---|---|---|
| `WIFI_AUDIT_AI` | `off` \| `ollama` \| `api` \| `auto` | `auto` |
| `WIFI_AUDIT_AI_BASE_URL` | URL base (sin `/chat/completions`) | Ollama local |
| `WIFI_AUDIT_AI_MODEL` | Modelo a usar | `minicpm-v` (Ollama) |
| `WIFI_AUDIT_AI_KEY` | Clave de API (cae a `LLM_API_KEY`) | — |
| `WIFI_AUDIT_AI_TIMEOUT` | Timeout HTTP en segundos | `60` |

Ejemplos:

```bash
# Ollama local (por defecto en modo auto si no hay URL)
export WIFI_AUDIT_AI=ollama
export WIFI_AUDIT_AI_MODEL=minicpm-v

# API remota compatible con OpenAI
export WIFI_AUDIT_AI=api
export WIFI_AUDIT_AI_BASE_URL=https://api.deepseek.com/v1
export WIFI_AUDIT_AI_MODEL=deepseek-chat
export WIFI_AUDIT_AI_KEY=sk-...

# Sin IA (solo tabla determinista)
export WIFI_AUDIT_AI=off
```

La IA se usa para tres cosas: **elegir el método** por AP, **interpretar los
resultados** (qué se capturó, qué falló) y **generar el análisis del informe**.

---

## Estructura del proyecto

```
wifi-audit-tui/
├── pyproject.toml
├── requirements.txt
├── run.sh
├── assets/
│   ├── wifi-audit-tui.desktop  # launcher de escritorio
│   └── wifi-audit-tui.svg      # icono
└── wifi_audit/
    ├── app.py                # App de Textual + estado global
    ├── app.tcss              # estilos
    ├── auth.py               # aviso legal / frase de autorización
    ├── config.py             # rutas, detección de root
    ├── diagnostics.py        # modo --check (diagnóstico sin TUI)
    ├── state.py              # estado de la sesión
    ├── core/
    │   ├── runner.py         # subprocess con streaming y parada por grupo
    │   ├── tools.py          # detección de la suite
    │   ├── interface.py      # airmon-ng: modo monitor
    │   ├── scanner.py        # parser del CSV de airodump-ng
    │   ├── cracker.py        # aircrack-ng
    │   ├── attacks.py        # aireplay-ng / airbase-ng
    │   ├── ai.py             # capa de IA (OpenAI-compatible / Ollama)
    │   ├── orchestrator.py   # flujo automatico y tabla de decision
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
- **MediaTek MT7921U** (y otros chipsets `mt76`) pueden cambiar a modo monitor
  pero **no capturar frames** — `airodump-ng` ve 0 redes. Usa un chipset
  probado (Atheros AR9271, Ralink RT5370/RT3070) para escaneo/captura real.
- El escaneo se refresca cada segundo; con cientos de APs la tabla puede
  actualizarse algo despacio (normal).

---

## Licencia

MIT. El autor no se hace responsable del uso indebido de la herramienta.
