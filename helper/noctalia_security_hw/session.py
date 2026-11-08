"""One run of the helper: the state the panel shows, and the one operation it was asked for."""

import asyncio

from . import fprint
from .common import log
from .fido import FidoMixin
from .gpg import GpgMixin
from .ssh import SshMixin


class Session(FidoMixin, GpgMixin, SshMixin):
    def __init__(self, runner, emit, paths, user, askpass_command, fingerprint=fprint.state):
        self.runner = runner
        self.emit = emit
        self.paths = paths
        self.user = user
        self.askpass_command = askpass_command
        self.fingerprint = fingerprint
        self.op = None
        self.task = None
        self.devices = []
        self.card = None
        self.primary = ""

    def fail(self, op, code, detail=""):
        self.emit({"type": "error", "op": op, "code": code, "detail": detail})

    async def execute(self, op, coroutine):
        """Runs one operation to its end. Whatever happens, the last event is
        {"type": "end", "op"}: the plugin's runStream has no exit callback."""
        self.op = op
        self.task = asyncio.ensure_future(coroutine)
        try:
            await self.task
        except asyncio.CancelledError:
            self.emit({"type": "cancelled", "op": op})
        except Exception as e:  # noqa: BLE001 - report it, the panel stays usable
            log("%s failed: %r" % (op, e))
            self.fail(op, "generic", str(e))
        finally:
            self.op = None
            self.task = None
            self.emit({"type": "end", "op": op})

    def cancel(self):
        if self.task is not None:
            self.runner.cancel()
            self.task.cancel()

    # -- state -----------------------------------------------------------

    async def probe(self):
        """The connected keys' device paths only: cheap enough to poll while the panel is open."""
        self.emit({"type": "probe", "devices": [d["path"] for d in await self.list_devices()]})

    async def refresh(self):
        await self.load_devices()
        await self.load_card()
        await self.emit_state()

    async def emit_state(self):
        key_state, trusted = await self.key_state()
        self.emit({
            "type": "state",
            "devices": self.devices,
            **self.fido_state(),
            "card": self.card,
            "keyState": key_state,
            "trusted": trusted,
            "sshKeys": self.ssh_entries(),
            "sshDefaults": self.ssh_defaults(),
            "sshInclude": self.ssh_include_state(),
            "fingerprint": self.fingerprint(),
        })
