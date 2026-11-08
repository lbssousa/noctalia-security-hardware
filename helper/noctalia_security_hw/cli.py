"""noctalia-security-hw: fingerprint readers, FIDO2/U2F keys, the OpenPGP card and resident SSH
keys, for the lbssousa/security-hardware Noctalia plugin.

One process per operation (a Luau plugin cannot write to a process's stdin), every line on
stdout a JSON event:

  {"type": "pid", "pid": N}            first, so the plugin can cancel with SIGTERM
  {"type": "state", …}                 everything the panel shows (after "state", and after
                                       every operation that changes something)
  {"type": "probe", "devices": [path]} the connected keys, for the panel's hot-plug poll
  {"type": "busy", "op", "stage"}      "touch" while a key waits for a touch, "scan" for a reader
  {"type": "done", "op", …}
  {"type": "error", "op", "code", "detail"}
  {"type": "cancelled", "op"}
  {"type": "end", "op"}                always last: runStream has no exit callback

Commands:
  state | probe
  fido register [--pin-file F]        pamu2fcfg, into pam_u2f's per-user authfile
  fido remove <key handle>
  fido test                           pamtester on $NOCTALIA_SECURITY_HW_U2F_SERVICE
                                      (default noctalia-lock-u2f)
  gpg import | trust | remove         the card's key: fetch or update, ultimate trust,
                                      out of the keyring (never a secret kept on disk)
  gpg import-file <path>
  ssh import [--pin-file F]           ssh-keygen -K, complete pairs into ~/.ssh, never over a file
  ssh create [--pin-file F] <json>    {"algorithm","application","user","verify","touch",
                                       "comment","replace"}
  ssh remove <name>                   the copy in ~/.ssh (the key stays on the security key)
  ssh delete [--pin-file F] <name>    that exact credential off the security key, then the copy
  ssh host <name> on|off [minutes]    ~/.ssh/config.d/<host>.conf for the git host it names
  ssh persist <name> <minutes>        connection reuse for that host, 0..1440
  fp list <device> | delete <device> <finger>
  fp enroll <device> <finger> | verify <device>

PINs come in a file the plugin writes (0600) under $XDG_RUNTIME_DIR/noctalia-security-hw: it is
read and removed at once and never put on a command line or in the environment. For ssh-keygen
the helper is its own SSH_ASKPASS, handing the PIN over a socket in a private folder.
"""

import asyncio
import json
import os
import signal
import sys

from . import fprint
from .common import Paths, Runner, user_name
from .pin import ASKPASS_ENV, PinFileError, askpass, take_pin
from .session import Session


def emit(event):
    try:
        print(json.dumps(event, ensure_ascii=False), flush=True)
    except BrokenPipeError:
        pass


class Usage(Exception):
    pass


def pop_pin(args, paths):
    """Takes "--pin-file F" out of <args> and returns the PIN it held ("" without one)."""
    if "--pin-file" not in args:
        return ""
    i = args.index("--pin-file")
    if i + 1 >= len(args):
        raise Usage("--pin-file needs a path")
    path = args[i + 1]
    del args[i:i + 2]
    return take_pin(path, paths.pins)


def minutes_arg(text):
    try:
        return int(text)
    except ValueError:
        return -1


def operation(session, area, action, args, pin):
    """The (op, coroutine) a command line asks for; Usage when it makes no sense."""
    def need(count):
        if len(args) != count:
            raise Usage("%s %s takes %d argument(s)" % (area, action, count))

    if area == "state":
        need(0)
        return "state", session.refresh()
    if area == "probe":
        need(0)
        return "probe", session.probe()
    if area == "fido":
        if action == "register":
            need(0)
            return "fido.register", session.fido_register(pin)
        if action == "remove":
            need(1)
            return "fido.remove", session.fido_remove(args[0])
        if action == "test":
            need(0)
            return "fido.test", session.fido_test()
    if area == "gpg":
        if action in ("import", "trust", "remove"):
            need(0)
            return "gpg." + action, getattr(session, "gpg_" + action)()
        if action == "import-file":
            need(1)
            return "gpg.import-file", session.gpg_import_file(args[0])
    if area == "ssh":
        if action == "import":
            need(0)
            return "ssh.import", session.ssh_import(pin)
        if action == "create":
            need(1)
            try:
                options = json.loads(args[0])
            except ValueError as e:
                raise Usage("ssh create takes a JSON object") from e
            if not isinstance(options, dict):
                raise Usage("ssh create takes a JSON object")
            return "ssh.create", session.ssh_create(options, pin)
        if action == "remove":
            need(1)
            return "ssh.remove", session.ssh_remove(args[0])
        if action == "delete":
            need(1)
            return "ssh.delete", session.ssh_delete(args[0], pin)
        if action == "host" and len(args) in (2, 3) and args[1] in ("on", "off"):
            minutes = minutes_arg(args[2]) if len(args) == 3 else None
            return "ssh.host", session.ssh_host(args[0], args[1] == "on", minutes)
        if action == "persist":
            need(2)
            return "ssh.persist", session.ssh_persist(args[0], minutes_arg(args[1]))
    raise Usage("unknown command")


# Operations that need to know the connected keys first.
NEEDS_DEVICES = {"fido.register", "ssh.import", "ssh.create", "ssh.delete"}
NEEDS_CARD = {"gpg.import", "gpg.import-file"}


async def run_session(argv):
    paths = Paths()
    command = os.environ.get("NOCTALIA_SECURITY_HW_SELF") or os.path.abspath(sys.argv[0])
    session = Session(Runner(), emit, paths, user_name(), command)
    area = argv[0] if argv else ""
    action = argv[1] if len(argv) > 1 and area not in ("state", "probe") else ""
    args = list(argv[2:] if action else argv[1:])
    op = area + ("." + action if action else "")
    try:
        pin = pop_pin(args, paths)
        op, coroutine = operation(session, area, action, args, pin)
    except (Usage, PinFileError) as e:
        emit({"type": "error", "op": op, "code": "usage", "detail": str(e)})
        emit({"type": "end", "op": op})
        return 2
    emit({"type": "pid", "pid": os.getpid()})
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        loop.add_signal_handler(signum, session.cancel)

    async def prepared():
        if op in NEEDS_DEVICES:
            await session.load_devices()
        if op in NEEDS_CARD:
            await session.load_card()
        await coroutine

    await session.execute(op, prepared())
    return 0


def run_fingerprint(argv):
    """fp commands: GLib's main loop, not asyncio (fprintd's signals)."""
    action = argv[1] if len(argv) > 1 else ""
    args = argv[2:]
    op = "fp." + action
    emit({"type": "pid", "pid": os.getpid()})
    try:
        if action == "list" and len(args) == 1:
            emit({"type": "done", "op": op, "enrolled": fprint.list_fingers(args[0])})
        elif action == "delete" and len(args) == 2:
            fprint.delete_finger(args[0], args[1])
            emit({"type": "done", "op": op, "finger": args[1]})
        elif action == "enroll" and len(args) == 2:
            fprint.operation(args[0], "enroll", args[1], emit)
        elif action == "verify" and len(args) == 1:
            fprint.operation(args[0], "verify", None, emit)
        else:
            emit({"type": "error", "op": op, "code": "usage", "detail": "unknown command"})
    except fprint.FprintError as e:
        emit({"type": "error", "op": op, "code": e.code, "detail": e.detail})
    except Exception as e:  # noqa: BLE001 - no GObject or no system bus
        emit({"type": "error", "op": op, "code": "generic", "detail": str(e)})
    emit({"type": "end", "op": op})
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # ssh-keygen runs SSH_ASKPASS with the prompt as its only argument; the
    # socket in the environment is what says this run is the askpass.
    if os.environ.get(ASKPASS_ENV):
        sys.exit(askpass(" ".join(argv)))
    if argv[:1] in (["-h"], ["--help"]) or not argv:
        print(__doc__)
        sys.exit(0 if argv else 2)
    if argv[0] == "fp":
        sys.exit(run_fingerprint(argv))
    sys.exit(asyncio.run(run_session(argv)))
