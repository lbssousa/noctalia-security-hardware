"""The OpenPGP card: its key in the keyring, the stubs that link it, the trust."""

import os
import re

from .common import GPG_TIMEOUT_S, NETWORK_TIMEOUT_S, PROBE_TIMEOUT_S, last_line, log


# -- parsers (pure, tested) ----------------------------------------------------

def unescape_colons(value):
    # gpg --with-colons escapes ':' and control characters as "\xHH".
    return re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), value)


def parse_card(text):
    """`gpg --card-status --with-colons`; None without an OpenPGP card."""
    fields = {}
    for line in text.splitlines():
        parts = line.split(":")
        fields.setdefault(parts[0], parts[1:])
    reader = fields.get("Reader")
    if reader is None or "openpgp-card" not in ":".join(reader):
        return None

    def get(name, index):
        values = fields.get(name, [])
        return unescape_colons(values[index]) if index < len(values) else ""

    holder = " ".join(part for part in (get("name", 0), get("name", 1)) if part)
    fingerprints = [f for f in fields.get("fpr", []) if re.fullmatch(r"[0-9A-Fa-f]{40,64}", f)]
    return {
        "vendor": get("vendor", 1),
        "serial": get("serial", 0),
        "holder": holder,
        "url": get("url", 0),
        "fingerprints": fingerprints,
    }


def primary_key(text):
    """The primary fingerprint and ownertrust of `gpg --list-keys --with-colons`."""
    trust = ""
    for line in text.splitlines():
        parts = line.split(":")
        if parts[0] in ("pub", "sec") and not trust:
            trust = parts[8] if len(parts) > 8 else ""
        elif parts[0] == "fpr" and len(parts) > 9:
            return parts[9], trust
    return "", trust


def secret_on_disk(colons):
    """Whether a --list-secret-keys --with-colons listing has a secret part that
    lives in the keyring rather than on a card. Field 15 holds the card's serial
    for a stub, "#" for a stub whose card is away, "+" for a real secret."""
    for line in colons.splitlines():
        fields = line.split(":")
        if fields[0] in ("sec", "ssb"):
            token = fields[14] if len(fields) > 14 else ""
            if token in ("", "+"):
                return True
    return False


class GpgMixin:
    """Session methods for the OpenPGP card (see session.Session)."""

    async def load_card(self):
        result = await self.runner.run(["gpg", "--card-status", "--with-colons"], timeout=PROBE_TIMEOUT_S)
        self.card = parse_card(result.out) if result.code == 0 else None

    async def key_state(self):
        """none / missing / public / ready for the card's key, and whether it is ultimately trusted."""
        self.primary = ""
        if not self.card or not self.card["fingerprints"]:
            return "none", False
        fpr = self.card["fingerprints"][0]
        public = await self.runner.run(["gpg", "--list-keys", "--with-colons", fpr], timeout=GPG_TIMEOUT_S)
        if public.code != 0:
            return "missing", False
        self.primary, trust = primary_key(public.out)
        secret = await self.runner.run(["gpg", "--list-secret-keys", "--with-colons", fpr], timeout=GPG_TIMEOUT_S)
        return ("ready" if secret.code == 0 and secret.out.strip() else "public"), trust == "u"

    async def gpg_import(self):
        op = "gpg.import"
        if not self.card:
            self.fail(op, "no-card")
            return
        updating = (await self.key_state())[0] == "ready"
        self.emit({"type": "busy", "op": op, "stage": "fetch"})
        imported = False
        url = self.card.get("url", "")
        if url.startswith(("https://", "http://", "hkps://", "hkp://")):
            result = await self.runner.run(["gpg", "--fetch-keys", url], timeout=NETWORK_TIMEOUT_S)
            imported = result.code == 0
            if not imported:
                log("gpg --fetch-keys failed:", last_line(result.err))
        if not imported and self.card["fingerprints"]:
            result = await self.runner.run(["gpg", "--recv-keys", self.card["fingerprints"][0]],
                                           timeout=NETWORK_TIMEOUT_S)
            imported = result.code == 0
            if not imported:
                log("gpg --recv-keys failed:", last_line(result.err))
        if not imported:
            self.fail(op, "import-failed")
            await self.emit_state()
            return
        await self.link_card()
        self.emit({"type": "done", "op": op, "updated": updating})
        await self.emit_state()

    async def link_card(self):
        # Reading the card again creates the secret-key stubs that point gpg at it.
        await self.runner.run(["gpg", "--card-status"], timeout=PROBE_TIMEOUT_S)

    async def gpg_import_file(self, path):
        op = "gpg.import-file"
        path = os.path.expanduser(path or "")
        if not path or not os.path.isfile(path):
            self.fail(op, "no-file", path)
            return
        self.emit({"type": "busy", "op": op, "stage": "import"})
        result = await self.runner.run(["gpg", "--batch", "--import", path], timeout=GPG_TIMEOUT_S)
        if result.code != 0:
            self.fail(op, "import-failed", last_line(result.err))
            await self.emit_state()
            return
        if self.card:
            await self.link_card()
        self.emit({"type": "done", "op": op})
        await self.emit_state()

    async def gpg_trust(self):
        op = "gpg.trust"
        await self.key_state()
        if not self.primary:
            self.fail(op, "trust-failed")
            return
        result = await self.runner.run(["gpg", "--import-ownertrust"], stdin="%s:6:\n" % self.primary,
                                       timeout=GPG_TIMEOUT_S)
        if result.code != 0:
            self.fail(op, "trust-failed", last_line(result.err))
            return
        self.emit({"type": "done", "op": op})
        await self.emit_state()

    async def gpg_remove(self):
        """Takes the card's key out of the keyring. Only ever stubs: a secret
        part kept on disk would be lost for good, so then nothing is removed."""
        op = "gpg.remove"
        await self.key_state()
        if not self.primary:
            self.fail(op, "remove-failed", "not in the keyring")
            return
        secret = await self.runner.run(["gpg", "--list-secret-keys", "--with-colons", self.primary],
                                       timeout=GPG_TIMEOUT_S)
        has_secret = secret.code == 0 and secret.out.strip() != ""
        if has_secret and secret_on_disk(secret.out):
            self.fail(op, "secret-on-disk")
            return
        what = "--delete-secret-and-public-keys" if has_secret else "--delete-keys"
        result = await self.runner.run(["gpg", "--batch", "--yes", what, self.primary], timeout=GPG_TIMEOUT_S)
        if result.code != 0:
            self.fail(op, "remove-failed", last_line(result.err))
            await self.emit_state()
            return
        self.emit({"type": "done", "op": op})
        await self.emit_state()
