#!/usr/bin/env python3
"""noctalia-security-hw: fingerprint readers, FIDO2/U2F keys and the OpenPGP card, for the
lbssousa/security-hardware Noctalia plugin.

One process per operation; every line on stdout is a JSON object. Long operations print
{"pid": N} first (the plugin cancels with SIGTERM) and always end with {"event": "done", ...},
since the plugin's runStream has no exit callback.

  fp state                       readers, default reader, availability
  fp list <device>               enrolled fingers on a reader
  fp enroll <device> <finger>    stream: status events, then done
  fp verify <device>             stream: status events, then done (30 s without a scan ends it)
  fp delete <device> <finger>
  key state                      pamu2fcfg/fido2-token, connected keys, registered credentials
  key register [<pin-file>]      stream: pamu2fcfg (touch), appends to the pam_u2f authfile;
                                 the PIN file is read and removed at once
  key remove <index>
  key test                       stream: pamtester on the "noctalia-lock-u2f" PAM service
                                 ($NOCTALIA_SECURITY_HW_U2F_SERVICE overrides it)
  gpg state                      OpenPGP card, key state, trust
  gpg import                     stream: card URL, then the keyservers; links the card stubs
  gpg import-file <path>         stream
  gpg trust                      ultimate ownertrust for the card's primary key

Ported from the old Noctalia settings patch (fingerprint_manager.cpp, security_key_manager.cpp).
"""

import json
import os
import pwd
import re
import shutil
import signal
import subprocess
import sys

FPRINT = "net.reactivated.Fprint"
MANAGER_PATH = "/net/reactivated/Fprint/Manager"
MANAGER_IFACE = "net.reactivated.Fprint.Manager"
DEVICE_IFACE = "net.reactivated.Fprint.Device"
FINGERS = [
    "right-thumb", "right-index-finger", "right-middle-finger", "right-ring-finger", "right-little-finger",
    "left-thumb", "left-index-finger", "left-middle-finger", "left-ring-finger", "left-little-finger",
]
VERIFY_TIMEOUT = 30
COMMAND_TIMEOUT = 20
REGISTER_TIMEOUT = 60
NETWORK_TIMEOUT = 60
# PAM service used by "key test"; override with NOCTALIA_SECURITY_HW_U2F_SERVICE.
U2F_SERVICE = os.environ.get("NOCTALIA_SECURITY_HW_U2F_SERVICE") or "noctalia-lock-u2f"


def emit(obj):
    print(json.dumps(obj, ensure_ascii=False), flush=True)


def fail(code, **extra):
    emit({"ok": False, "error": code, **extra})
    sys.exit(1)


def user_name():
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return os.environ.get("USER", "")


def last_line(text):
    lines = [line for line in (text or "").splitlines() if line.strip()]
    return lines[-1] if lines else ""


def run(args, timeout=COMMAND_TIMEOUT, stdin_data=None):
    """Runs a command with untranslated output (it is parsed). Returns (rc, out, err, timed_out)."""
    env = dict(os.environ, LC_ALL="C")
    try:
        proc = subprocess.run(
            args, input=stdin_data, capture_output=True, text=True, timeout=timeout, env=env,
            stdin=None if stdin_data is not None else subprocess.DEVNULL,
        )
        return proc.returncode, proc.stdout, proc.stderr, False
    except subprocess.TimeoutExpired as exc:
        return -1, exc.stdout or "", exc.stderr or "", True
    except OSError as exc:
        return -1, "", str(exc), False


# ── Fingerprint (fprintd over D-Bus) ─────────────────────────────────────────────────────────
#
# The fprintd CLI tools only ever enroll and verify on the default reader, and a claim lives as
# long as the D-Bus connection that made it, so this needs one process holding one connection.

def fp_bus():
    from gi.repository import Gio  # noqa: PLC0415 (only the fp commands need GObject)

    return Gio, Gio.bus_get_sync(Gio.BusType.SYSTEM, None)


def fp_proxy(gio, bus, path, iface):
    return gio.DBusProxy.new_sync(bus, gio.DBusProxyFlags.NONE, None, FPRINT, path, iface, None)


def fp_error_code(exc):
    text = str(exc)
    for needle, code in (
        ("AlreadyInUse", "in-use"),
        ("PermissionDenied", "permission-denied"),
        ("NoSuchDevice", "no-device"),
        ("NoEnrolledPrints", "no-prints"),
        ("PrintsNotDeleted", "not-deleted"),
    ):
        if needle in text:
            return code
    return "generic"


def fp_call(proxy, method, signature=None, args=(), timeout_ms=10000):
    from gi.repository import GLib, Gio  # noqa: PLC0415

    params = GLib.Variant(signature, args) if signature else None
    return proxy.call_sync(method, params, Gio.DBusCallFlags.NONE, timeout_ms, None)


def fp_available(gio, bus):
    from gi.repository import GLib  # noqa: PLC0415

    dbus = gio.DBusProxy.new_sync(
        bus, gio.DBusProxyFlags.NONE, None, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", None,
    )
    names = set()
    for method in ("ListNames", "ListActivatableNames"):
        try:
            names.update(dbus.call_sync(method, None, gio.DBusCallFlags.NONE, 5000, None).unpack()[0])
        except GLib.Error:
            pass
    return FPRINT in names


def fp_state():
    from gi.repository import GLib  # noqa: PLC0415

    gio, bus = fp_bus()
    if not fp_available(gio, bus):
        emit({"available": False, "devices": [], "default": ""})
        return
    manager = fp_proxy(gio, bus, MANAGER_PATH, MANAGER_IFACE)
    try:
        paths = fp_call(manager, "GetDevices").unpack()[0]
    except GLib.Error as exc:
        emit({"available": True, "devices": [], "default": "", "error": fp_error_code(exc)})
        return
    default = ""
    try:
        default = fp_call(manager, "GetDefaultDevice").unpack()[0]
    except GLib.Error:
        pass
    devices = []
    for path in paths:
        device = fp_proxy(gio, bus, path, DEVICE_IFACE)
        name = device.get_cached_property("name")
        scan = device.get_cached_property("scan-type")
        devices.append({
            "path": path,
            "name": name.unpack() if name is not None else path,
            "scan_type": scan.unpack() if scan is not None else "press",
        })
    emit({"available": True, "devices": devices, "default": default})


def fp_device(path):
    if not re.fullmatch(r"/net/reactivated/Fprint/Device/[0-9]+", path or ""):
        fail("no-device")
    gio, bus = fp_bus()
    return gio, bus, fp_proxy(gio, bus, path, DEVICE_IFACE)


def fp_list(path):
    from gi.repository import GLib  # noqa: PLC0415

    _, _, device = fp_device(path)
    try:
        fingers = fp_call(device, "ListEnrolledFingers", "(s)", (user_name(),)).unpack()[0]
    except GLib.Error as exc:
        code = fp_error_code(exc)
        if code == "no-prints":
            fingers = []
        else:
            fail(code, message=str(exc))
    emit({"ok": True, "enrolled": list(fingers)})


def fp_delete(path, finger):
    from gi.repository import GLib  # noqa: PLC0415

    if finger not in FINGERS:
        fail("generic", message="unknown finger")
    _, _, device = fp_device(path)
    try:
        fp_call(device, "Claim", "(s)", (user_name(),))
    except GLib.Error as exc:
        fail(fp_error_code(exc), message=str(exc))
    try:
        fp_call(device, "DeleteEnrolledFinger", "(s)", (finger,))
    except GLib.Error as exc:
        fail(fp_error_code(exc), message=str(exc))
    finally:
        try:
            fp_call(device, "Release")
        except GLib.Error:
            pass
    emit({"ok": True})


def fp_operation(path, mode, finger=None):
    """Enroll or verify, streaming fprintd's status codes until done."""
    from gi.repository import GLib  # noqa: PLC0415

    if mode == "enroll" and finger not in FINGERS:
        fail("generic", message="unknown finger")
    _, _, device = fp_device(path)
    emit({"pid": os.getpid()})
    loop = GLib.MainLoop()
    state = {"claimed": False, "running": False, "result": None}
    stages = device.get_cached_property("num-enroll-stages")
    stages_total = stages.unpack() if stages is not None else -1

    def finish(ok, code, **extra):
        if state["result"] is not None:
            return
        state["result"] = {"event": "done", "ok": ok, "code": code, **extra}
        if state["running"]:
            try:
                fp_call(device, "EnrollStop" if mode == "enroll" else "VerifyStop")
            except GLib.Error:
                pass
        if state["claimed"]:
            try:
                fp_call(device, "Release")
            except GLib.Error:
                pass
        loop.quit()

    def on_signal(_proxy, _sender, signal_name, params):
        if mode == "enroll" and signal_name == "EnrollStatus":
            result, done = params.unpack()
            emit({"event": "status", "code": result, "stages_total": stages_total})
            if done:
                finish(result == "enroll-completed", result)
        elif mode == "verify" and signal_name == "VerifyFingerSelected":
            emit({"event": "finger", "finger": params.unpack()[0]})
        elif mode == "verify" and signal_name == "VerifyStatus":
            result, done = params.unpack()
            emit({"event": "status", "code": result})
            if done:
                finish(result == "verify-match", result)

    device.connect("g-signal", on_signal)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, sig, lambda: (finish(False, "cancelled"), False)[1])

    try:
        fp_call(device, "Claim", "(s)", (user_name(),))
        state["claimed"] = True
        if mode == "enroll":
            fp_call(device, "EnrollStart", "(s)", (finger,))
        else:
            fp_call(device, "VerifyStart", "(s)", ("any",))
            GLib.timeout_add_seconds(VERIFY_TIMEOUT, lambda: (finish(False, "verify-timeout"), False)[1])
        state["running"] = True
    except GLib.Error as exc:
        finish(False, fp_error_code(exc), message=str(exc))
        emit(state["result"])
        return

    loop.run()
    emit(state["result"])


# ── FIDO2 / U2F (pam_u2f) ────────────────────────────────────────────────────────────────────

def authfile_path():
    # Same lookup as pam_u2f's default authfile.
    base = os.environ.get("XDG_CONFIG_HOME") or ""
    if not base:
        home = os.environ.get("HOME") or pwd.getpwuid(os.getuid()).pw_dir
        base = os.path.join(home, ".config")
    return os.path.join(base, "Yubico", "u2f_keys")


def read_credentials(user):
    """user:KeyHandle,PublicKey,CoseType,Options[:KeyHandle2,...] -> raw credential strings."""
    creds = []
    try:
        with open(authfile_path(), encoding="utf-8") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if not line.startswith(user + ":"):
                    continue
                creds.extend(cred for cred in line[len(user) + 1:].split(":") if cred)
    except FileNotFoundError:
        pass
    return creds


def write_credentials(user, creds):
    path = authfile_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    kept, replaced = [], False
    joined = ":".join([user, *creds])
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if line.startswith(user + ":"):
                    if not replaced and creds:
                        kept.append(joined)
                    replaced = True
                elif line:
                    kept.append(line)
    except FileNotFoundError:
        pass
    if not replaced and creds:
        kept.append(joined)
    tmp = path + ".tmp"
    old = os.umask(0o077)
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            handle.writelines(line + "\n" for line in kept)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False
    finally:
        os.umask(old)
    return True


def connected_keys():
    if shutil.which("fido2-token"):
        # "/dev/hidraw4: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)"
        rc, out, _, _ = run(["fido2-token", "-L"])
        keys = []
        for line in out.splitlines() if rc == 0 else []:
            match = re.search(r"\((.*)\)\s*$", line)
            keys.append(match.group(1) if match else line.strip())
        return [key for key in keys if key]
    if shutil.which("ykman"):
        rc, out, _, _ = run(["ykman", "list"])
        return [line for line in out.splitlines() if line.strip()] if rc == 0 else []
    return []


def key_state():
    user = user_name()
    creds = read_credentials(user)
    emit({
        "tools": shutil.which("pamu2fcfg") is not None,
        "test_service": any(os.path.exists(p) for p in (f"/etc/pam.d/{U2F_SERVICE}", f"/usr/lib/pam.d/{U2F_SERVICE}")),
        "tester": shutil.which("pamtester") is not None,
        "authfile": authfile_path(),
        "connected": connected_keys(),
        "credentials": [{"handle": cred.split(",", 1)[0]} for cred in creds],
    })


def take_pin(path):
    """The plugin writes the PIN to a 0600 file in its own runtime dir; read it and remove it."""
    if not path:
        return ""
    runtime = os.environ.get("XDG_RUNTIME_DIR", "")
    real = os.path.realpath(path)
    if not runtime or os.path.dirname(real) != os.path.realpath(os.path.join(runtime, "noctalia-security-hw")):
        fail("generic", message="PIN file outside the runtime dir")
    try:
        with open(real, encoding="utf-8") as handle:
            pin = handle.read().strip("\n")
    except OSError:
        pin = ""
    try:
        os.unlink(real)
    except OSError:
        pass
    return pin


def key_register(pin_file=None):
    user = user_name()
    pin = take_pin(pin_file)
    emit({"pid": os.getpid()})
    if not user or not shutil.which("pamu2fcfg"):
        emit({"event": "done", "ok": False, "code": "register-failed", "message": "pamu2fcfg"})
        return
    emit({"event": "status", "code": "touch"})
    # Without a terminal, pamu2fcfg reads the PIN from stdin.
    rc, out, err, timed_out = run(
        ["pamu2fcfg", "-u", user], timeout=REGISTER_TIMEOUT, stdin_data=(pin + "\n") if pin else None,
    )
    pin = ""
    line = last_line(out)
    colon = line.find(":")
    if rc != 0 or colon < 0 or colon + 1 >= len(line):
        if timed_out:
            code = "timeout"
        elif "PIN" in err:
            code = "pin-required"
        elif "No device" in err or "No FIDO" in err:
            code = "no-device"
        else:
            code = "register-failed"
        emit({"event": "done", "ok": False, "code": code, "message": last_line(err)})
        return
    creds = read_credentials(user)
    creds.append(line[colon + 1:])
    if not write_credentials(user, creds):
        emit({"event": "done", "ok": False, "code": "write-failed", "path": authfile_path()})
        return
    emit({"event": "done", "ok": True, "code": "registered"})


def key_remove(index):
    user = user_name()
    creds = read_credentials(user)
    try:
        i = int(index)
    except ValueError:
        fail("generic")
    if i < 0 or i >= len(creds):
        fail("generic")
    del creds[i]
    if not write_credentials(user, creds):
        fail("write-failed", path=authfile_path())
    emit({"ok": True, "code": "removed"})


def key_test():
    emit({"pid": os.getpid()})
    if not shutil.which("pamtester"):
        emit({"event": "done", "ok": False, "code": "test-no-key"})
        return
    emit({"event": "status", "code": "testing"})
    env = dict(os.environ, LC_ALL="C")
    proc = subprocess.Popen(
        ["pamtester", U2F_SERVICE, user_name(), "authenticate"], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
    )

    def stop(_sig, _frame):
        proc.terminate()

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)
    cued = False
    for line in proc.stdout:
        # pam_u2f's cue ("Please touch the FIDO authenticator.")
        if "touch" in line.lower():
            cued = True
            emit({"event": "status", "code": "touch"})
    rc = proc.wait()
    if rc == 0:
        emit({"event": "done", "ok": True, "code": "test-ok"})
    elif rc < 0:
        emit({"event": "done", "ok": False, "code": "cancelled"})
    else:
        emit({"event": "done", "ok": False, "code": "test-timeout" if cued else "test-no-key"})


# ── OpenPGP card (gpg) ───────────────────────────────────────────────────────────────────────

def unescape_colons(field):
    # gpg --with-colons escapes ':' and control characters as C-style "\xHH".
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), field)


def colon_records(text):
    for line in text.splitlines():
        if line:
            yield [unescape_colons(field) for field in line.split(":")]


def card_info():
    rc, out, _, _ = run(["gpg", "--card-status", "--with-colons"])
    if rc != 0:
        return None
    card = {"reader": "", "vendor": "", "serial": "", "holder": "", "url": "", "fingerprints": []}
    for fields in colon_records(out):
        kind = fields[0]
        get = lambda i: fields[i] if i < len(fields) else ""  # noqa: E731
        if kind == "Reader":
            card["reader"] = get(1)
        elif kind == "vendor":
            card["vendor"] = get(2)
        elif kind == "serial":
            card["serial"] = get(1)
        elif kind == "name":
            card["holder"] = " ".join(part for part in (get(1), get(2)) if part)
        elif kind == "url":
            card["url"] = get(1)
        elif kind == "fpr":
            card["fingerprints"] = [get(i) for i in (1, 2, 3) if get(i)]
    return card


def key_status(card):
    """("unknown"|"missing"|"public-only"|"ready", trusted, primary fingerprint)."""
    if card is None or not card["fingerprints"]:
        return "unknown", False, ""
    fpr = card["fingerprints"][0]
    on_card, serial = False, ""
    _, secret, _, _ = run(["gpg", "--list-secret-keys", "--with-colons", fpr])
    for fields in colon_records(secret):
        if fields[0] in ("sec", "ssb"):
            serial = fields[14] if len(fields) > 14 else ""
        elif fields[0] == "fpr" and len(fields) > 9 and fields[9] in card["fingerprints"]:
            # A key on a card shows the card serial in field 15 of its sec/ssb record.
            if serial and serial != "#":
                on_card = True
    rc, public, _, _ = run(["gpg", "--list-keys", "--with-colons", fpr])
    trusted, primary, after_pub = False, "", False
    for fields in colon_records(public):
        if fields[0] == "pub":
            trusted = len(fields) > 8 and fields[8] == "u"
            after_pub = True
        elif fields[0] == "fpr" and after_pub:
            primary = fields[9] if len(fields) > 9 else ""
            after_pub = False
    if rc != 0:
        return "missing", False, ""
    return ("ready" if on_card else "public-only"), trusted, primary


def gpg_state():
    if not shutil.which("gpg"):
        emit({"gpg": False})
        return
    card = card_info()
    state, trusted, primary = key_status(card)
    emit({"gpg": True, "card": card, "state": state, "trusted": trusted, "primary": primary})


def gpg_link_stubs():
    # Reading the card with the public key in the keyring links the secret-key stubs to it.
    run(["gpg", "--card-status"])


def gpg_import():
    emit({"pid": os.getpid()})
    card = card_info()
    if card is None or not card["fingerprints"]:
        emit({"event": "done", "ok": False, "code": "import-failed"})
        return
    if card["url"]:
        emit({"event": "status", "code": "fetching-url"})
        rc, _, _, _ = run(["gpg", "--fetch-keys", card["url"]], timeout=NETWORK_TIMEOUT)
        if rc == 0:
            gpg_link_stubs()
            emit({"event": "done", "ok": True, "code": "imported"})
            return
    emit({"event": "status", "code": "fetching-keyserver"})
    # Uses the keyserver configured for gpg/dirmngr.
    rc, _, _, _ = run(["gpg", "--recv-keys", card["fingerprints"][0]], timeout=NETWORK_TIMEOUT)
    if rc == 0:
        gpg_link_stubs()
        emit({"event": "done", "ok": True, "code": "imported"})
    else:
        emit({"event": "done", "ok": False, "code": "import-failed"})


def gpg_import_file(path):
    emit({"pid": os.getpid()})
    emit({"event": "status", "code": "importing-file"})
    rc, _, err, _ = run(["gpg", "--import", os.path.expanduser(path)])
    if rc == 0:
        gpg_link_stubs()
        emit({"event": "done", "ok": True, "code": "imported"})
    else:
        emit({"event": "done", "ok": False, "code": "import-file-failed", "message": last_line(err)})


def gpg_trust():
    _, _, primary = key_status(card_info())
    if not primary:
        fail("trust-failed", message="no key")
    rc, _, err, _ = run(["gpg", "--import-ownertrust"], stdin_data=primary + ":6:\n")
    if rc != 0:
        fail("trust-failed", message=last_line(err))
    emit({"ok": True, "code": "trusted"})


COMMANDS = {
    ("fp", "state"): (fp_state, 0),
    ("fp", "list"): (fp_list, 1),
    ("fp", "enroll"): (lambda dev, finger: fp_operation(dev, "enroll", finger), 2),
    ("fp", "verify"): (lambda dev: fp_operation(dev, "verify"), 1),
    ("fp", "delete"): (fp_delete, 2),
    ("key", "state"): (key_state, 0),
    ("key", "register"): (key_register, None),
    ("key", "remove"): (key_remove, 1),
    ("key", "test"): (key_test, 0),
    ("gpg", "state"): (gpg_state, 0),
    ("gpg", "import"): (gpg_import, 0),
    ("gpg", "import-file"): (gpg_import_file, 1),
    ("gpg", "trust"): (gpg_trust, 0),
}


def main(argv):
    if len(argv) < 3 or (argv[1], argv[2]) not in COMMANDS:
        print(__doc__, file=sys.stderr)
        return 2
    func, arity = COMMANDS[(argv[1], argv[2])]
    args = argv[3:]
    if arity is not None and len(args) != arity:
        print(__doc__, file=sys.stderr)
        return 2
    func(*args)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
