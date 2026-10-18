#!/usr/bin/env python3
"""Runs the real `pio run -e <maintenance env>` commands against a fake board on a pty.

No hardware needed: a thread plays the firmware's serial protocol (see
HardwareEsp32::processSerialLine). Verifies framing, the answers, and the safety rules.
  python3 test/tools/test_device_storage.py
"""
import base64, os, pty, subprocess, sys, threading, time, tty

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PIO = os.path.expanduser("~/.platformio/penv/bin/pio")


class FakeBoard(threading.Thread):
    def __init__(self, reply):
        super().__init__(daemon=True)
        self.master, self.slave = pty.openpty()
        tty.setraw(self.master)
        self.port = os.ttyname(self.slave)
        self.reply = reply          # fn(line) -> bytes to send back (or None)
        self.lines = []
        self.stop = False

    def run(self):
        buf = b""
        os.write(self.master, b"I (123) boot: noisy log line without newline ")  # junk before the first command
        while not self.stop:
            try:
                data = os.read(self.master, 256)
            except OSError:
                return
            buf += data
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                line = raw.decode("ascii", "replace").strip()
                if not line:
                    continue
                self.lines.append(line)
                answer = self.reply(line)
                if answer:
                    os.write(self.master, answer)


def run_env(env_name, board, extra_env=None, timeout=90):
    env = dict(os.environ)
    env.pop("ESCAPE_DEVICE_PORT", None)
    env.update(extra_env or {})
    return subprocess.run([PIO, "run", "-e", env_name], cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout)


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  -> " + detail))
    return cond


def main():
    ok = True
    # --- token: answer shares a line with log output; first send ignored (board still booting)
    seen = {"n": 0}
    def token_reply(line):
        seen["n"] += 1
        if seen["n"] == 1:
            return None                     # no answer on the first attempt: the tool must resend
        return b"I (9) boot: " + b"ESCAPE_AUTH_TOKEN_OK\r\n"
    b = FakeBoard(token_reply); b.start()
    r = run_env("update-auth-token", b, {"ESCAPE_DEVICE_PORT": b.port, "ESCAPE_AUTH_TOKEN": "a-long-random-token-value-1234"})
    sent = [l for l in b.lines if l.startswith("ESCAPE_AUTH_TOKEN")]
    ok &= check("token: success after resend", r.returncode == 0 and "Auth token stored" in r.stdout, r.stdout[-300:] + r.stderr[-300:])
    ok &= check("token: base64 payload, never plain", bool(sent) and base64.b64decode(sent[0].split(" ", 1)[1]) == b"a-long-random-token-value-1234" and "a-long-random" not in sent[0])
    ok &= check("token: resent after silence", len(sent) >= 2)
    b.stop = True

    # --- short token: allowed with warning; too short / spaces rejected before any serial traffic
    b = FakeBoard(lambda l: b"ESCAPE_AUTH_TOKEN_OK\n"); b.start()
    r = run_env("update-auth-token", b, {"ESCAPE_DEVICE_PORT": b.port, "ESCAPE_AUTH_TOKEN": "shorttoken1"})
    ok &= check("short token: warns but works", r.returncode == 0 and "WARNING" in r.stdout, r.stdout[-300:])
    r = run_env("update-auth-token", b, {"ESCAPE_DEVICE_PORT": b.port, "ESCAPE_AUTH_TOKEN": "tiny"})
    ok &= check("token < 8 rejected", r.returncode != 0 and "8 to 128" in (r.stdout + r.stderr))
    r = run_env("update-auth-token", b, {"ESCAPE_DEVICE_PORT": b.port, "ESCAPE_AUTH_TOKEN": "has a space inside"})
    ok &= check("token with space rejected", r.returncode != 0)
    b.stop = True

    # --- board rejects
    b = FakeBoard(lambda l: b"ESCAPE_AUTH_TOKEN_ERROR storage\n"); b.start()
    r = run_env("update-auth-token", b, {"ESCAPE_DEVICE_PORT": b.port, "ESCAPE_AUTH_TOKEN": "a-long-random-token-value-1234"})
    ok &= check("board error is reported", r.returncode != 0 and "rejected" in (r.stdout + r.stderr))
    b.stop = True

    # --- wifi
    b = FakeBoard(lambda l: b"ESCAPE_WIFI_OK\n" if l.startswith("ESCAPE_WIFI ") else None); b.start()
    r = run_env("set-wifi", b, {"ESCAPE_DEVICE_PORT": b.port, "ESCAPE_WIFI_SSID": "Mein Netz äö", "ESCAPE_WIFI_PASSWORD": "pa ss=word"})
    parts = [l for l in b.lines if l.startswith("ESCAPE_WIFI ")]
    ok &= check("wifi: stored", r.returncode == 0 and bool(parts), r.stdout[-300:] + r.stderr[-300:])
    if parts:
        s, p = parts[0].split(" ")[1:3]
        ok &= check("wifi: payload round-trips (spaces, umlauts)", base64.b64decode(s).decode() == "Mein Netz äö" and base64.b64decode(p).decode() == "pa ss=word")
    r = run_env("set-wifi", b, {"ESCAPE_DEVICE_PORT": b.port})
    ok &= check("wifi: ssid required", r.returncode != 0 and "SSID" in (r.stdout + r.stderr))
    b.stop = True

    # --- info prints the answer line
    b = FakeBoard(lambda l: b"ESCAPE_INFO_OK did=aabbccddeeff fw=2.0.0 proto=2 token=default ip=1.2.3.4 heap=200000\n" if l == "ESCAPE_INFO" else None); b.start()
    r = run_env("device-info", b, {"ESCAPE_DEVICE_PORT": b.port})
    ok &= check("info: prints the board's answer", r.returncode == 0 and "did=aabbccddeeff" in r.stdout, r.stdout[-300:])
    b.stop = True

    # --- reset needs an explicit port and sends exactly one command
    b = FakeBoard(lambda l: b"ESCAPE_RESET_STORAGE_OK\n" if l == "ESCAPE_RESET_STORAGE" else None); b.start()
    r = run_env("reset-persistent-storage", b, {})
    ok &= check("reset: refuses without explicit port", r.returncode != 0 and "explicitly" in (r.stdout + r.stderr) and not b.lines, r.stdout[-300:])
    r = run_env("reset-persistent-storage", b, {"ESCAPE_DEVICE_PORT": b.port})
    ok &= check("reset: works with explicit port", r.returncode == 0 and "ESCAPE_RESET_STORAGE" in b.lines, r.stdout[-300:])
    b.stop = True

    print("ALL OK" if ok else "FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
