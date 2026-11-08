"""Fingerprint readers through fprintd's D-Bus API.

The fprintd command-line tools only ever enroll and verify on the default reader, and a
claim lives as long as the D-Bus connection that made it, so this needs one process
holding one connection. GObject (Gio) is only imported here.
"""

import re
import signal

from .common import user_name

FPRINT = "net.reactivated.Fprint"
MANAGER_PATH = "/net/reactivated/Fprint/Manager"
MANAGER_IFACE = "net.reactivated.Fprint.Manager"
DEVICE_IFACE = "net.reactivated.Fprint.Device"
DEVICE_PATH = re.compile(r"/net/reactivated/Fprint/Device/[0-9]+")
FINGERS = [
    "right-thumb", "right-index-finger", "right-middle-finger", "right-ring-finger", "right-little-finger",
    "left-thumb", "left-index-finger", "left-middle-finger", "left-ring-finger", "left-little-finger",
]
VERIFY_TIMEOUT_S = 30


class FprintError(Exception):
    def __init__(self, code, detail=""):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def error_code(exc):
    text = str(exc)
    for needle, code in (
        ("AlreadyInUse", "fp-in-use"),
        ("PermissionDenied", "fp-permission-denied"),
        ("NoSuchDevice", "fp-no-device"),
        ("NoEnrolledPrints", "fp-no-prints"),
        ("PrintsNotDeleted", "fp-not-deleted"),
    ):
        if needle in text:
            return code
    return "generic"


def _gi():
    from gi.repository import Gio, GLib  # noqa: PLC0415

    return Gio, GLib


def _bus():
    gio, _ = _gi()
    return gio.bus_get_sync(gio.BusType.SYSTEM, None)


def _proxy(bus, path, iface):
    gio, _ = _gi()
    return gio.DBusProxy.new_sync(bus, gio.DBusProxyFlags.NONE, None, FPRINT, path, iface, None)


def _call(proxy, method, signature=None, args=(), timeout_ms=10000):
    gio, glib = _gi()
    params = glib.Variant(signature, args) if signature else None
    return proxy.call_sync(method, params, gio.DBusCallFlags.NONE, timeout_ms, None)


def _available(bus):
    gio, glib = _gi()
    dbus = gio.DBusProxy.new_sync(bus, gio.DBusProxyFlags.NONE, None, "org.freedesktop.DBus",
                                  "/org/freedesktop/DBus", "org.freedesktop.DBus", None)
    names = set()
    for method in ("ListNames", "ListActivatableNames"):
        try:
            names.update(dbus.call_sync(method, None, gio.DBusCallFlags.NONE, 5000, None).unpack()[0])
        except glib.Error:
            pass
    return FPRINT in names


def state():
    """{"available", "devices": [{"path", "name", "scanType"}], "default"}; never raises."""
    empty = {"available": False, "devices": [], "default": ""}
    try:
        _, glib = _gi()
        bus = _bus()
    except Exception:  # noqa: BLE001 - no GObject, no system bus: no reader
        return empty
    try:
        if not _available(bus):
            return empty
        manager = _proxy(bus, MANAGER_PATH, MANAGER_IFACE)
        paths = _call(manager, "GetDevices").unpack()[0]
    except glib.Error:
        return dict(empty, available=True)
    default = ""
    try:
        default = _call(manager, "GetDefaultDevice").unpack()[0]
    except glib.Error:
        pass
    devices = []
    for path in paths:
        device = _proxy(bus, path, DEVICE_IFACE)
        name = device.get_cached_property("name")
        scan = device.get_cached_property("scan-type")
        devices.append({"path": path, "name": name.unpack() if name is not None else path,
                        "scanType": scan.unpack() if scan is not None else "press"})
    return {"available": True, "devices": devices, "default": default}


def _device(path):
    if not DEVICE_PATH.fullmatch(path or ""):
        raise FprintError("fp-no-device", path or "")
    return _proxy(_bus(), path, DEVICE_IFACE)


def list_fingers(path):
    _, glib = _gi()
    device = _device(path)
    try:
        return list(_call(device, "ListEnrolledFingers", "(s)", (user_name(),)).unpack()[0])
    except glib.Error as exc:
        if error_code(exc) == "fp-no-prints":
            return []
        raise FprintError(error_code(exc), str(exc)) from exc


def delete_finger(path, finger):
    _, glib = _gi()
    if finger not in FINGERS:
        raise FprintError("generic", "unknown finger")
    device = _device(path)
    try:
        _call(device, "Claim", "(s)", (user_name(),))
    except glib.Error as exc:
        raise FprintError(error_code(exc), str(exc)) from exc
    try:
        _call(device, "DeleteEnrolledFinger", "(s)", (finger,))
    except glib.Error as exc:
        raise FprintError(error_code(exc), str(exc)) from exc
    finally:
        try:
            _call(device, "Release")
        except glib.Error:
            pass


def operation(path, mode, finger, emit):
    """Enroll or verify, emitting fprintd's status as "busy" events until it ends:
    {"type": "done", "op", "finger"?} or an "error" with fprintd's result as its code
    ("enroll-duplicate", "verify-no-match", …), or "cancelled" on SIGTERM."""
    _, glib = _gi()
    op = "fp." + mode
    if mode == "enroll" and finger not in FINGERS:
        raise FprintError("generic", "unknown finger")
    device = _device(path)
    loop = glib.MainLoop()
    st = {"claimed": False, "running": False, "result": None, "finger": ""}
    stages = device.get_cached_property("num-enroll-stages")
    stages_total = stages.unpack() if stages is not None else -1

    def finish(event):
        if st["result"] is not None:
            return
        st["result"] = event
        if st["running"]:
            try:
                _call(device, "EnrollStop" if mode == "enroll" else "VerifyStop")
            except glib.Error:
                pass
        if st["claimed"]:
            try:
                _call(device, "Release")
            except glib.Error:
                pass
        loop.quit()

    def on_signal(_proxy, _sender, signal_name, params):
        if mode == "enroll" and signal_name == "EnrollStatus":
            result, done = params.unpack()
            emit({"type": "busy", "op": op, "stage": "scan", "status": result, "stagesTotal": stages_total})
            if done:
                finish({"type": "done", "op": op, "finger": finger} if result == "enroll-completed"
                       else {"type": "error", "op": op, "code": result, "detail": ""})
        elif mode == "verify" and signal_name == "VerifyFingerSelected":
            st["finger"] = params.unpack()[0]
        elif mode == "verify" and signal_name == "VerifyStatus":
            result, done = params.unpack()
            emit({"type": "busy", "op": op, "stage": "scan", "status": result})
            if done:
                finish({"type": "done", "op": op, "finger": st["finger"]} if result == "verify-match"
                       else {"type": "error", "op": op, "code": result, "detail": ""})

    device.connect("g-signal", on_signal)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        glib.unix_signal_add(glib.PRIORITY_DEFAULT, sig,
                             lambda: (finish({"type": "cancelled", "op": op}), False)[1])
    try:
        _call(device, "Claim", "(s)", (user_name(),))
        st["claimed"] = True
        if mode == "enroll":
            _call(device, "EnrollStart", "(s)", (finger,))
        else:
            _call(device, "VerifyStart", "(s)", ("any",))
            glib.timeout_add_seconds(VERIFY_TIMEOUT_S, lambda: (
                finish({"type": "error", "op": op, "code": "verify-timeout", "detail": ""}), False)[1])
        st["running"] = True
        emit({"type": "busy", "op": op, "stage": "scan", "status": "started", "stagesTotal": stages_total})
    except glib.Error as exc:
        finish({"type": "error", "op": op, "code": error_code(exc), "detail": str(exc)})
        emit(st["result"])
        return
    loop.run()
    emit(st["result"])

