# PlatformIO-Environments fuer Wartungsaktionen am bereits laufenden ESP32.
# Beide Aktionen kommunizieren nur ueber USB-Serial und flashen keine Firmware.
# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUndefinedVariable=false

Import("env")

from SCons.Script import Default

import base64
import os
import time


AUTH_COMMAND_PREFIX = b"ESCAPE_AUTH_TOKEN "
AUTH_SUCCESS = "ESCAPE_AUTH_TOKEN_OK"
AUTH_ERROR_PREFIX = "ESCAPE_AUTH_TOKEN_ERROR"
RESET_COMMAND = b"ESCAPE_RESET_STORAGE\n"
RESET_SUCCESS = "ESCAPE_RESET_STORAGE_OK"
RESET_ERROR_PREFIX = "ESCAPE_RESET_STORAGE_ERROR"
MIN_TOKEN_LENGTH = 8
MAX_TOKEN_LENGTH = 128


def _project_option(name, default=""):
    value = env.GetProjectOption(name, default)
    return str(value).strip() if value is not None else default


def _auth_token():
    token = os.environ.get("ESCAPE_AUTH_TOKEN", "").strip()
    if not token:
        token = _project_option("custom_auth_token")

    try:
        encoded = token.encode("ascii")
    except UnicodeEncodeError as error:
        raise RuntimeError("Auth-Token muss aus druckbaren ASCII-Zeichen bestehen") from error

    if not MIN_TOKEN_LENGTH <= len(encoded) <= MAX_TOKEN_LENGTH:
        raise RuntimeError("Auth-Token muss 8 bis 128 Zeichen lang sein")
    if any(value < 0x21 or value > 0x7E for value in encoded):
        raise RuntimeError("Auth-Token darf keine Leer- oder Steuerzeichen enthalten")
    return encoded


def _device_port():
    port = _project_option("custom_device_port")
    if not port:
        # Enthaelt sowohl upload_port aus der INI als auch --upload-port von
        # der Kommandozeile; ein nicht expandierter Platzhalter gilt als leer.
        port = env.subst("$UPLOAD_PORT").strip()
        if "$" in port:
            port = ""
    if not port:
        env.AutodetectUploadPort()
        port = env.subst("$UPLOAD_PORT").strip()
    if not port or "$" in port:
        raise RuntimeError("Kein serieller Port gefunden; custom_device_port setzen")
    return port


def _send_serial_command(command, success_response, error_prefix, start_message, success_message):
    try:
        import serial
    except ImportError as error:
        raise RuntimeError("PlatformIO-Python enthaelt kein pyserial") from error

    port = _device_port()
    baud = int(_project_option("monitor_speed", "115200"))
    print(start_message.format(port=port))

    try:
        connection = serial.Serial()
        connection.port = port
        connection.baudrate = baud
        connection.timeout = 0.25
        connection.write_timeout = 2
        # Beide Leitungen deaktiviert halten. Falls der USB-UART-Adapter beim
        # Oeffnen trotzdem resettiert, deckt die Wiederholung den Boot ab.
        connection.dtr = False
        connection.rts = False
        connection.open()
    except serial.SerialException as error:
        raise RuntimeError(
            "Serieller Port {} konnte nicht geoeffnet werden; Monitor schliessen".format(port)
        ) from error

    deadline = time.monotonic() + 35.0
    next_send = 0.0
    try:
        connection.reset_input_buffer()
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_send:
                connection.write(command)
                connection.flush()
                next_send = now + 1.5

            response = connection.readline().decode("ascii", errors="replace").strip()
            if response == success_response:
                print(success_message)
                return 0
            if response.startswith(error_prefix):
                raise RuntimeError("Board hat die Wartungsaktion abgelehnt: " + response)
    finally:
        connection.close()

    raise RuntimeError(
        "Keine Antwort vom Board; Port, Firmware-Version und monitor_speed pruefen"
    )


def _update_auth_token(source, target, env):
    del source, target, env
    token = _auth_token()
    command = AUTH_COMMAND_PREFIX + base64.b64encode(token) + b"\n"
    return _send_serial_command(
        command,
        AUTH_SUCCESS,
        AUTH_ERROR_PREFIX,
        "Schreibe Auth-Token ueber {port} (Firmware wird nicht geflasht) ...",
        "Auth-Token wurde persistent gespeichert; das Board startet neu.",
    )


def _reset_persistent_storage(source, target, env):
    del source, target, env
    return _send_serial_command(
        RESET_COMMAND,
        RESET_SUCCESS,
        RESET_ERROR_PREFIX,
        "Loesche persistenten Speicher ueber {port} (Firmware bleibt unveraendert) ...",
        "Persistenter Speicher wurde geloescht; das Board startet neu.",
    )


action_name = _project_option("custom_device_action")
if action_name == "update-auth-token":
    action = _update_auth_token
    title = "Update persistent auth token"
    description = "Writes only escfg/authtoken over Serial; does not flash firmware"
elif action_name == "reset-persistent-storage":
    action = _reset_persistent_storage
    title = "Reset persistent storage"
    description = "Clears only the escfg NVS namespace over Serial; does not flash firmware"
else:
    raise RuntimeError("Unbekannte custom_device_action: " + action_name)

maintenance_target = env.AddCustomTarget(
    name=action_name,
    dependencies=None,
    actions=[action],
    title=title,
    description=description,
    always_build=True,
)

# Fuer die beiden Wartungs-Environments ist die jeweilige serielle Aktion das
# Default-Ziel. Dadurch genuegt `pio run -e <environment>` und PlatformIO baut
# weder das Programm noch eine Dateisystem-/Partitionsabbilddatei.
env["SIZETOOL"] = None
Default(None)
Default(maintenance_target)
