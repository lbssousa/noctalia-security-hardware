"""What every part of the helper shares: running programs, paths, libfido2's errors."""

import asyncio
import os
import pwd
import signal
import sys
import tempfile

TOUCH_TIMEOUT_S = 60
GPG_TIMEOUT_S = 30
NETWORK_TIMEOUT_S = 45
PROBE_TIMEOUT_S = 10
AUTH_TIMEOUT_S = 120
# Making a resident SSH key waits for a touch, twice when it replaces one.
CREATE_TIMEOUT_S = 120

# The PAM service "fido test" authenticates against; NixOS gets it from the
# nix-config lock screen (pam_u2f alone). Override with this variable.
TEST_SERVICE_ENV = "NOCTALIA_SECURITY_HW_U2F_SERVICE"
TEST_SERVICE = "noctalia-lock-u2f"
# The services whose pam_u2f lines say where keys must be registered.
PAM_SERVICES = (("sudo", "sudo"), ("polkit-1", "polkit"))

# libfido2's error names, as pamu2fcfg, fido2-token and ssh-keygen print them,
# to the codes the panel explains.
FIDO_ERRORS = (
    ("PIN_INVALID", "pin-invalid"),
    ("PIN incorrect", "pin-invalid"),
    ("PIN_AUTH_BLOCKED", "pin-blocked"),
    ("PIN_BLOCKED", "pin-blocked"),
    ("Too many incorrect PINs", "pin-blocked"),
    ("PIN_REQUIRED", "pin-required"),
    ("pin required", "pin-required"),
    ("failed to read pin", "pin-required"),
    ("couldn't read PIN", "pin-required"),
    ("ACTION_TIMEOUT", "timeout"),
    ("USER_ACTION_TIMEOUT", "timeout"),
    ("No device found", "no-device"),
    ("No FIDO SecurityKeyProvider", "no-device"),
    ("device not found", "no-device"),
    ("fido_dev_open", "no-device"),
    ("No keys to download", "ssh-none"),
    ("no keys found", "ssh-none"),
    ("returned no keys", "ssh-none"),
)


def log(*parts):
    print("noctalia-security-hw:", *parts, file=sys.stderr, flush=True)


def last_line(text):
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[-1] if lines else ""


def fido_error(text, pin=""):
    # Asked for a PIN it wasn't given (pamu2fcfg then fails on the empty one).
    if not pin and "Enter PIN" in text:
        return "pin-required"
    for needle, code in FIDO_ERRORS:
        if needle in text:
            return code
    return "generic"


def user_name():
    name = os.environ.get("USER")
    if name:
        return name
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return ""


def replace_file(path, text, mode):
    """Writes <path> whole, or not at all."""
    fd, temporary = tempfile.mkstemp(prefix="." + os.path.basename(path) + "-", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


class Result:
    def __init__(self, code, out="", err=""):
        self.code = code
        self.out = out
        self.err = err


class Runner:
    """Runs one program at a time for an operation; cancel() kills it."""

    def __init__(self):
        self.proc = None

    async def run(self, args, stdin=None, env=None, cwd=None, timeout=None):
        # Untranslated output: it is parsed.
        env = dict(env if env is not None else os.environ, LC_ALL="C")
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, env=env, cwd=cwd, start_new_session=True)
        except FileNotFoundError:
            return Result(127, "", "%s: not found" % args[0])
        self.proc = proc
        try:
            out, err = await asyncio.wait_for(proc.communicate(stdin.encode() if stdin else b""), timeout)
        except asyncio.TimeoutError:
            self.kill(proc)
            await proc.wait()
            return Result(-1, "", "timeout")
        finally:
            if self.proc is proc:
                self.proc = None
        return Result(proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"))

    def kill(self, proc=None):
        proc = proc or self.proc
        if proc is not None and proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def cancel(self):
        self.kill()


class Paths:
    def __init__(self, home=None, config=None, pam_dirs=None, runtime=None):
        self.home = home or os.path.expanduser("~")
        # pam_u2f's default authfile: $XDG_CONFIG_HOME/Yubico/u2f_keys, else ~/.config.
        self.config = config or os.environ.get("XDG_CONFIG_HOME") or os.path.join(self.home, ".config")
        self.pam_dirs = pam_dirs or ["/etc/pam.d", "/usr/lib/pam.d"]
        self.runtime = runtime or os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()

    @property
    def authfile(self):
        return os.path.join(self.config, "Yubico", "u2f_keys")

    @property
    def ssh(self):
        return os.path.join(self.home, ".ssh")

    @property
    def pins(self):
        """Where the plugin leaves PINs for the helper (0700, under the runtime dir)."""
        return os.path.join(self.runtime, "noctalia-security-hw")

    def pam_file(self, service):
        for directory in self.pam_dirs:
            path = os.path.join(directory, service)
            if os.path.isfile(path):
                return path
        return ""
