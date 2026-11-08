"""FIDO2/U2F keys for pam_u2f: devices, where sudo and polkit read keys, registering."""

import base64
import os
import re
import socket
import tempfile

from .common import (PAM_SERVICES, PROBE_TIMEOUT_S, TEST_SERVICE, TEST_SERVICE_ENV, TOUCH_TIMEOUT_S, AUTH_TIMEOUT_S,
                     fido_error, last_line, log)


# -- parsers (pure, tested) ----------------------------------------------------

def parse_devices(text):
    """`fido2-token -L`: "/dev/hidraw1: vendor=0x1050, product=0x0407 (Yubico YubiKey …)"."""
    devices = []
    for line in text.splitlines():
        path, sep, rest = line.partition(": ")
        if not sep or not path.startswith("/"):
            continue
        name = re.search(r"\((.*)\)\s*$", rest)
        devices.append({"path": path, "name": name.group(1) if name else rest.strip()})
    return devices


def parse_info(text):
    """`fido2-token -I <dev>`: the options and PIN retries that decide what the panel offers."""
    options = []
    retries = -1
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key = key.strip()
        if key == "options":
            options = [o.strip() for o in value.split(",") if o.strip()]
        elif key == "pin retries":
            try:
                retries = int(value.strip())
            except ValueError:
                pass
    return {"rk": "rk" in options, "clientPin": "clientPin" in options, "pinRetries": retries}


def credential_handles(line, user):
    """The credentials on <user>'s line of a pam_u2f authfile ("user:cred[:cred…]")."""
    if not line.startswith(user + ":"):
        return []
    return [c for c in line[len(user) + 1:].split(":") if c]


def credential_label(credential):
    # "keyHandle,publicKey,coseType,options": a short, stable prefix of the
    # key handle tells two keys apart.
    return credential.split(",", 1)[0][:10]


def merge_credentials(existing, new):
    """Appends credentials not on the list yet, by key handle. A key registered
    twice gets a new handle each time: already_registered() catches that."""
    merged = list(existing)
    handles = {c.split(",", 1)[0] for c in existing}
    for credential in new:
        handle = credential.split(",", 1)[0]
        if handle and handle not in handles:
            merged.append(credential)
            handles.add(handle)
    return merged


def pam_u2f(text):
    """Whether a PAM file uses pam_u2f, the authfile it fixes ("" = pam_u2f's
    per-user default), and whether it demands the key's PIN."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#") or "pam_u2f.so" not in line:
            continue
        authfile = ""
        words = line.split()
        for word in words:
            if word.startswith("authfile="):
                authfile = word[len("authfile="):]
        return {"u2f": True, "authfile": authfile, "pin": "pinverification=1" in words}
    return {"u2f": False, "authfile": "", "pin": False}


class FidoMixin:
    """Session methods for pam_u2f keys (see session.Session)."""

    async def list_devices(self):
        result = await self.runner.run(["fido2-token", "-L"], timeout=PROBE_TIMEOUT_S)
        return parse_devices(result.out) if result.code == 0 else []

    async def load_devices(self):
        devices = await self.list_devices()
        for device in devices:
            info = await self.runner.run(["fido2-token", "-I", device["path"]], timeout=PROBE_TIMEOUT_S)
            device.update(parse_info(info.out) if info.code == 0 else parse_info(""))
        self.devices = devices

    def pam_state(self):
        state = {}
        for service, name in PAM_SERVICES:
            path = self.paths.pam_file(service)
            try:
                with open(path, encoding="utf-8") as f:
                    state[name] = pam_u2f(f.read())
            except OSError:
                state[name] = {"u2f": False, "authfile": "", "pin": False}
        return state

    def pam_paths(self, pam):
        """The files the services that use pam_u2f read keys from."""
        own = os.path.normpath(self.paths.authfile)
        return {os.path.normpath(s["authfile"]) if s["authfile"] else own for s in pam.values() if s["u2f"]}

    def fido_target(self, pam=None):
        """Where a key registered now would go, and whether sudo and polkit would read it:
          own         the user's own list (pam_u2f's default), which they read
          no-pam      neither asks for a key
          other-file  they read a file the helper doesn't write (authfile=…)
          mixed       they read different files, so a key would only work for one
        """
        paths = self.pam_paths(pam or self.pam_state())
        if not paths:
            return {"kind": "no-pam", "path": ""}
        if len(paths) > 1:
            return {"kind": "mixed", "path": ""}
        path = paths.pop()
        return {"kind": "own" if path == os.path.normpath(self.paths.authfile) else "other-file", "path": path}

    def pin_required(self, pam=None):
        """Whether sudo or polkit only take a key with its PIN, so one without a PIN would never work."""
        return any(s["u2f"] and s["pin"] for s in (pam or self.pam_state()).values())

    def read_credentials(self, path=None):
        try:
            with open(path or self.paths.authfile, encoding="utf-8") as f:
                lines = f.read().splitlines()
        except OSError:
            return [], []
        mine = []
        others = []
        for line in lines:
            if line.startswith(self.user + ":"):
                mine.extend(credential_handles(line, self.user))
            elif line.strip():
                others.append(line)
        return mine, others

    def other_count(self, target):
        """How many of the user's keys the file sudo and polkit read holds, when it isn't
        the user's own list (-1 when it can't be read)."""
        if target["kind"] != "other-file":
            return 0
        try:
            with open(target["path"], encoding="utf-8") as f:
                return sum(len(credential_handles(line, self.user)) for line in f.read().splitlines())
        except OSError:
            return -1

    def test_service(self):
        return os.environ.get(TEST_SERVICE_ENV) or TEST_SERVICE

    def fido_state(self):
        pam = self.pam_state()
        target = self.fido_target(pam)
        unused = os.path.normpath(self.paths.authfile) not in self.pam_paths(pam)
        credentials = [{"handle": c.split(",", 1)[0], "label": credential_label(c), "unused": unused}
                       for c in self.read_credentials()[0]]
        return {
            "credentials": credentials,
            "target": target,
            "otherCount": self.other_count(target),
            "pinRequired": self.pin_required(pam),
            "testService": self.test_service() if self.paths.pam_file(self.test_service()) else "",
        }

    async def fido_register(self, pin):
        op = "fido.register"
        if not self.devices:
            self.fail(op, "no-device")
            return
        target = self.fido_target()
        if target["kind"] != "own":
            self.fail(op, "not-target", target["kind"])
            return
        if self.pin_required() and not self.devices[0].get("clientPin"):
            self.fail(op, "no-pin")
            return
        if await self.already_registered(self.read_credentials()[0]):
            self.fail(op, "already-registered")
            return
        self.emit({"type": "busy", "op": op, "stage": "touch"})
        # Without a terminal pamu2fcfg reads the PIN from stdin.
        result = await self.runner.run(["pamu2fcfg", "-u", self.user], stdin=(pin + "\n") if pin else None,
                                       timeout=TOUCH_TIMEOUT_S)
        if result.code != 0:
            code = "timeout" if result.err == "timeout" else fido_error(result.err, pin)
            log("pamu2fcfg failed:", last_line(result.err))
            self.fail(op, code, last_line(result.err))
            # The key may have been pulled out, or its PIN retries changed.
            await self.refresh()
            return
        new = credential_handles(last_line(result.out), self.user)
        if not new:
            self.fail(op, "generic", "pamu2fcfg")
            return
        mine, others = self.read_credentials()
        if not self.write_credentials(merge_credentials(mine, new), others):
            self.fail(op, "write-failed", self.paths.authfile)
            return
        self.emit({"type": "done", "op": op})
        await self.emit_state()

    async def already_registered(self, credentials):
        """Whether the key plugged in made one of <credentials>. A credential only
        answers on its own key, and up=false asks for no touch. Anything else
        (another origin, a key that refuses to answer) just isn't a match."""
        origin = "pam://" + socket.gethostname()
        for credential in credentials:
            challenge = base64.b64encode(os.urandom(32)).decode()
            result = await self.runner.run(["fido2-assert", "-G", "-t", "up=false", self.devices[0]["path"]],
                                           stdin="%s\n%s\n%s\n" % (challenge, origin, credential.split(",", 1)[0]),
                                           timeout=PROBE_TIMEOUT_S)
            if result.code == 0:
                return True
        return False

    async def fido_remove(self, handle):
        """Removes one of the user's keys, by its key handle: a stable reference, so a
        list that changed meanwhile can't make it remove another key."""
        op = "fido.remove"
        mine, others = self.read_credentials()
        kept = [c for c in mine if c.split(",", 1)[0] != handle]
        if not handle or len(kept) == len(mine):
            self.fail(op, "generic", "no such key")
            return
        if not self.write_credentials(kept, others):
            self.fail(op, "write-failed", self.paths.authfile)
            return
        self.emit({"type": "done", "op": op})
        await self.emit_state()

    async def fido_test(self):
        """Authenticates against the test PAM service with pamtester: the key plugged in
        has to be one registered here, and pam_u2f asks for its touch."""
        op = "fido.test"
        service = self.test_service()
        if not self.paths.pam_file(service):
            self.fail(op, "no-test-service", service)
            return
        self.emit({"type": "busy", "op": op, "stage": "touch"})
        result = await self.runner.run(["pamtester", service, self.user, "authenticate"], timeout=AUTH_TIMEOUT_S)
        if result.code == 0:
            self.emit({"type": "done", "op": op})
        elif result.err == "timeout":
            self.fail(op, "timeout")
        else:
            log("pamtester failed:", last_line(result.err or result.out))
            self.fail(op, "test-failed", last_line(result.err or result.out))

    def write_credentials(self, mine, others):
        """Rewrites the authfile with <user>'s line (dropped when empty), atomically, 0600."""
        lines = list(others)
        if mine:
            lines.append(":".join([self.user] + mine))
        path = self.paths.authfile
        directory = os.path.dirname(path)
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".u2f_keys.", dir=directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write("".join(line + "\n" for line in lines))
                    f.flush()
                    os.fsync(f.fileno())
                os.chmod(tmp, 0o600)
                os.replace(tmp, path)
            except BaseException:
                os.unlink(tmp)
                raise
        except OSError as e:
            log("could not write %s: %s" % (path, e))
            return False
        return True
