# PlatformIO maintenance environments for an ESP32 that is already running the library.
# They talk over USB-serial only and never flash firmware:
#
#   pio run -e update-auth-token       store an own token (ESCAPE_AUTH_TOKEN env or custom_auth_token)
#   pio run -e set-wifi                store Wi-Fi credentials (ESCAPE_WIFI_SSID/ESCAPE_WIFI_PASSWORD env
#                                      or custom_wifi_ssid/custom_wifi_password)
#   pio run -e device-info             print device id, versions, token state, IP, heap
#   pio run -e reset-persistent-storage  erase ALL stored settings (needs an explicit port, see below)
#
# Port: custom_device_port in platformio.ini, or the ESCAPE_DEVICE_PORT environment variable.
# Leaving it empty auto-detects the port for the harmless actions; the destructive reset
# always requires it so the wrong board cannot be wiped by accident.
# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUndefinedVariable=false

Import("env")

from SCons.Script import COMMAND_LINE_TARGETS, Default

import base64
import os
import time

clt = [str(t) for t in COMMAND_LINE_TARGETS]
if getattr(env, "IsBuildDump", lambda: False)() or any("ide" in t for t in clt):
    Return()

MIN_TOKEN_LENGTH = 8
MAX_TOKEN_LENGTH = 128
RECOMMENDED_TOKEN_LENGTH = 20
RESPONSE_TIMEOUT_S = 35.0
RESEND_INTERVAL_S = 1.5


def _project_option(name, default=""):
    value = env.GetProjectOption(name, default)
    return str(value).strip() if value is not None else default


def _setting(env_name, option_name):
    value = os.environ.get(env_name, "").strip()
    return value or _project_option(option_name)


def _auth_token():
    token = _setting("ESCAPE_AUTH_TOKEN", "custom_auth_token")
    try:
        encoded = token.encode("ascii")
    except UnicodeEncodeError as error:
        raise RuntimeError("Auth token must consist of printable ASCII characters") from error
    if not MIN_TOKEN_LENGTH <= len(encoded) <= MAX_TOKEN_LENGTH:
        raise RuntimeError("Auth token must be %d to %d characters long" % (MIN_TOKEN_LENGTH, MAX_TOKEN_LENGTH))
    if any(value < 0x21 or value > 0x7E for value in encoded):
        raise RuntimeError("Auth token must not contain spaces or control characters")
    if len(encoded) < RECOMMENDED_TOKEN_LENGTH:
        print("WARNING: a token below %d characters is easier to guess from recorded traffic" % RECOMMENDED_TOKEN_LENGTH)
    return encoded


def _device_port(required=False):
    port = _setting("ESCAPE_DEVICE_PORT", "custom_device_port")
    if port:
        return port
    if required:
        raise RuntimeError("This action is destructive: set custom_device_port or ESCAPE_DEVICE_PORT explicitly")
    port = env.subst("$UPLOAD_PORT").strip()
    if not port or "$" in port:
        env.AutodetectUploadPort()
        port = env.subst("$UPLOAD_PORT").strip()
    if not port or "$" in port:
        raise RuntimeError("No serial port found; set custom_device_port or ESCAPE_DEVICE_PORT")
    return port


def _send_serial_command(command, ok_prefix, error_prefix, start_message, success_message, required_port=False, show=False):
    """Sends `command` until the board answers; matches WHOLE lines so partial reads and log
    output sharing a line with the answer cannot confuse it."""
    try:
        import serial
    except ImportError as error:
        raise RuntimeError("PlatformIO's Python has no pyserial") from error

    port = _device_port(required_port)
    baud = int(_project_option("monitor_speed", "115200"))
    print(start_message.format(port=port))
    try:
        connection = serial.Serial()
        connection.port = port
        connection.baudrate = baud
        connection.timeout = 0.2
        connection.write_timeout = 2
        connection.dtr = False
        connection.rts = False
        connection.open()
    except serial.SerialException as error:
        raise RuntimeError("Could not open %s - close the serial monitor first" % port) from error

    buffer = b""
    deadline = time.monotonic() + RESPONSE_TIMEOUT_S
    next_send = 0.0
    try:
        connection.reset_input_buffer()
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_send:
                # A leading newline ends any half-typed line left in the board's buffer.
                connection.write(b"\n" + command)
                connection.flush()
                next_send = now + RESEND_INTERVAL_S
            buffer += connection.read(256)
            while b"\n" in buffer:
                raw, buffer = buffer.split(b"\n", 1)
                line = raw.decode("ascii", errors="replace").strip()
                # The answer may follow log output on the same line: look for it anywhere.
                for marker, handler in ((error_prefix, "error"), (ok_prefix, "ok")):
                    index = line.find(marker)
                    if index >= 0:
                        answer = line[index:]
                        if handler == "error":
                            raise RuntimeError("The board rejected the request: " + answer)
                        if show:
                            print(answer)
                        print(success_message)
                        return 0
            if len(buffer) > 4096:
                buffer = buffer[-512:]
    finally:
        connection.close()
    raise RuntimeError("No answer from the board; check the port, firmware version and monitor_speed")


def _b64(text):
    return base64.b64encode(text.encode("utf-8") if isinstance(text, str) else text)


def _update_auth_token(source, target, env):
    del source, target, env
    token = _auth_token()
    return _send_serial_command(
        b"ESCAPE_AUTH_TOKEN " + _b64(token) + b"\n", "ESCAPE_AUTH_TOKEN_OK", "ESCAPE_AUTH_TOKEN_ERROR",
        "Writing the auth token over {port} (no firmware is flashed) ...",
        "Auth token stored; the board restarts. Every manager must use the same token.",
    )


def _set_wifi(source, target, env):
    del source, target, env
    ssid = _setting("ESCAPE_WIFI_SSID", "custom_wifi_ssid")
    password = _setting("ESCAPE_WIFI_PASSWORD", "custom_wifi_password")
    if not ssid or len(ssid.encode("utf-8")) > 32:
        raise RuntimeError("Wi-Fi SSID is required (1..32 bytes): ESCAPE_WIFI_SSID or custom_wifi_ssid")
    if len(password.encode("utf-8")) > 63:
        raise RuntimeError("Wi-Fi password is at most 63 bytes")
    return _send_serial_command(
        b"ESCAPE_WIFI " + _b64(ssid) + b" " + _b64(password) + b"\n", "ESCAPE_WIFI_OK", "ESCAPE_WIFI_ERROR",
        "Writing the Wi-Fi credentials over {port} ...", "Wi-Fi credentials stored; the board restarts and connects.",
    )


def _device_info(source, target, env):
    del source, target, env
    return _send_serial_command(
        b"ESCAPE_INFO\n", "ESCAPE_INFO_OK", "ESCAPE_ERROR",
        "Asking the board on {port} ...", "Done.", show=True,
    )


def _reset_persistent_storage(source, target, env):
    del source, target, env
    return _send_serial_command(
        b"ESCAPE_RESET_STORAGE\n", "ESCAPE_RESET_STORAGE_OK", "ESCAPE_RESET_STORAGE_ERROR",
        "Erasing ALL persistent settings over {port} (the firmware stays) ...",
        "Storage erased; the board restarts with default token, names and rooms.", required_port=True,
    )


ACTIONS = {
    "update-auth-token": (_update_auth_token, "Update persistent auth token", "Stores the token in NVS; does not flash firmware"),
    "set-wifi": (_set_wifi, "Set Wi-Fi credentials", "Stores SSID/password in NVS; does not flash firmware"),
    "device-info": (_device_info, "Print device info", "Prints id, versions, token state, IP and heap"),
    "reset-persistent-storage": (_reset_persistent_storage, "Reset persistent storage", "Erases all stored settings over Serial; does not flash firmware"),
}

action_name = _project_option("custom_device_action")
if action_name not in ACTIONS:
    raise RuntimeError("Unknown custom_device_action: %r (expected one of %s)" % (action_name, ", ".join(sorted(ACTIONS))))
action, title, description = ACTIONS[action_name]

maintenance_target = env.AddCustomTarget(
    name=action_name,
    dependencies=None,
    actions=[action],
    title=title,
    description=description,
    always_build=True,
)

env["SIZETOOL"] = None
Default(None)
Default(maintenance_target)
