"""Aviso legal y contrato de autorizacion.

La aplicacion no realiza ninguna operacion activa hasta que el operador
confirma explicitamente que dispone de autorizacion por escrito sobre las
redes que va a auditar. La confirmacion queda registrada en el informe.
"""

from __future__ import annotations

AUTH_PHRASE = "AUTORIZADO"

LEGAL_NOTICE = """\
Esta herramienta envuelve la suite aircrack-ng y permite operaciones ACTIVAS
sobre redes inalambricas (desautenticacion, inyeccion de trafico, captura de
handshakes y creacion de puntos de acceso).

Su uso sobre redes que no te pertenecen o para las que no dispones de
autorizacion escrita y explicita es DELITO en la mayoria de jurisdicciones
(por ejemplo, arts. 197 bis y 264 del Codigo Penal espanol, Computer Fraud
and Abuse Act en EE. UU., etc.).

Al continuar, confirmas que:

  1. Eres el propietario de las redes a auditar, o tienes autorizacion
     escrita del propietario para realizar pruebas de seguridad.
  2. Entiendes que la actividad activa puede degradar o interrumpir el
     servicio de las redes objetivo.
  3. Asumes toda la responsabilidad legal del uso que hagas de la aplicacion.

Necesitas privilegios de root para operar. Esta confirmacion se registra en
el informe de sesion con fecha y hora.
"""
