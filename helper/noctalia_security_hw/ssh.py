"""Resident SSH keys: copies in ~/.ssh, new keys, deleting them, the git hosts they name."""

import base64
import hashlib
import os
import re
import secrets
import shutil
import socket
import tempfile

from .common import AUTH_TIMEOUT_S, CREATE_TIMEOUT_S, TOUCH_TIMEOUT_S, fido_error, last_line, log, replace_file
from .pin import ASKPASS_ENV, serve_pin

# Resident SSH keys: the names ssh-keygen gives them, the key types, and what a
# new key's application (after "ssh:") and user ID may hold. No slashes or "..",
# so the handle's name stays a plain file name in ~/.ssh.
RESIDENT = re.compile(r"id_\w+_sk_rk")
SSH_ALGORITHMS = {"ed25519-sk": "ed25519_sk", "ecdsa-sk": "ecdsa_sk"}
SK_KEY_TYPES = {"sk-ssh-ed25519@openssh.com": "ed25519-sk", "sk-ecdsa-sha2-nistp256@openssh.com": "ecdsa-sk"}
CREATE_APPLICATION = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._@:-]{0,126}[A-Za-z0-9])?")
CREATE_USER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._@-]{0,62}[A-Za-z0-9])?")
SSH_FILE_LIMIT = 65536
# `fido2-token -L -k`: "NN: <credential id> <display name…> <user id> <type> <prot>".
CREDENTIAL_ID = re.compile(r"[A-Za-z0-9+/]{16,1024}={0,2}")

# Git hosts named by a resident key's application (ssh:github.com,
# ssh:login@host:port): each gets a drop-in in ~/.ssh/config.d that uses its
# keys without the SSH agent. Only well-known forges, or hosts with "git" in a
# label before the top-level domain.
GIT_APPLICATION = re.compile(r"(?://)?(?:(?P<login>[A-Za-z0-9][A-Za-z0-9._-]*)@)?"
                             r"(?P<host>[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
                             r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+)"
                             r"(?::(?P<port>[0-9]{1,5}))?/?")
GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht",
             "gitea.com", "ssh.dev.azure.com", "vs-ssh.visualstudio.com"}
DROP_IN_MARKER = ("# Written by the Noctalia security-hardware plugin (lbssousa/security-hardware);"
                  " remove this line to keep your edits.")
IDENTITY = "    IdentityFile ~/.ssh/"
SSH_INCLUDE = "Include config.d/*.conf"
# Connection reuse per git host: 0 (the default) authenticates every new
# connection; up to 1440 minutes keeps a master connection that later ones
# reuse without the PIN or a touch.
CONTROL_PERSIST_MINUTES = 0
MAX_PERSIST_MINUTES = 1440
CONTROL_DIR = "noctalia-security-hw/control"


class SshConfigError(Exception):
    """An SSH configuration file the helper must leave alone; code is the panel's."""

    def __init__(self, code, detail=""):
        super().__init__(detail)
        self.code = code
        self.detail = detail


# -- parsers (pure, tested) ----------------------------------------------------

def ssh_string(data, at):
    """One length-prefixed string of an SSH wire blob, and where the next starts."""
    if at + 4 > len(data):
        raise ValueError("truncated SSH data")
    length = int.from_bytes(data[at:at + 4], "big")
    end = at + 4 + length
    if end > len(data):
        raise ValueError("truncated SSH data")
    return data[at + 4:end], end


def sk_public(blob):
    """The key type and application of a security-key public blob."""
    name, at = ssh_string(blob, 0)
    key_type = SK_KEY_TYPES.get(name.decode("ascii", "replace"))
    if key_type is None:
        raise ValueError("not a security-key public key")
    if key_type == "ecdsa-sk":
        _, at = ssh_string(blob, at)  # the curve
    _, at = ssh_string(blob, at)  # the point
    application, at = ssh_string(blob, at)
    if at != len(blob):
        raise ValueError("trailing public-key data")
    return key_type, application.decode("ascii")


def parse_public(text):
    """A resident key's .pub line: {"type", "application", "blob"}, or None."""
    fields = text.split()
    if len(fields) < 2 or fields[0] not in SK_KEY_TYPES:
        return None
    try:
        blob = base64.b64decode(fields[1], validate=True)
        key_type, application = sk_public(blob)
    except (ValueError, UnicodeError):
        return None
    if SK_KEY_TYPES[fields[0]] != key_type:
        return None
    return {"type": key_type, "application": application, "blob": blob}


def fingerprint(blob):
    """The SHA256 fingerprint ssh-keygen -l prints for a public blob."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def parse_handle(text):
    """A resident key's private file (the handle ssh-keygen writes, not a secret):
    {"blob", "encrypted", "credential"}; the credential ID is None when the file
    has a passphrase. Raises ValueError for anything else."""
    begin, end = "-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----"
    if begin not in text or end not in text:
        raise ValueError("not an OpenSSH key file")
    body = text.split(begin, 1)[1].split(end, 1)[0]
    data = base64.b64decode("".join(body.split()), validate=True)
    magic = b"openssh-key-v1\0"
    if not data.startswith(magic):
        raise ValueError("not an OpenSSH key file")
    cipher, at = ssh_string(data, len(magic))
    _, at = ssh_string(data, at)  # KDF name
    _, at = ssh_string(data, at)  # KDF options
    if data[at:at + 4] != b"\0\0\0\1":
        raise ValueError("expected exactly one key")
    blob, at = ssh_string(data, at + 4)
    private, _ = ssh_string(data, at)
    if cipher != b"none":
        return {"blob": blob, "encrypted": True, "credential": None}
    # Two check integers, then the key: its type, the public part, the
    # application, the flags byte and the key handle (the credential ID).
    if len(private) < 8 or private[0:4] != private[4:8]:
        raise ValueError("damaged key file")
    name, at = ssh_string(private, 8)
    key_type = SK_KEY_TYPES.get(name.decode("ascii", "replace"))
    if key_type is None:
        raise ValueError("not a security-key handle")
    if key_type == "ecdsa-sk":
        _, at = ssh_string(private, at)  # the curve
    _, at = ssh_string(private, at)  # the point
    _, at = ssh_string(private, at)  # the application
    at += 1  # the flags
    credential, _ = ssh_string(private, at)
    if not credential:
        raise ValueError("no key handle")
    return {"blob": blob, "encrypted": False, "credential": credential}


def token_credentials(text):
    """The credentials of a `fido2-token -L -k <application>` listing, by ID (bytes)."""
    found = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5 or not fields[0].endswith(":") or not CREDENTIAL_ID.fullmatch(fields[1]):
            continue
        try:
            found.append({"id": fields[1], "raw": base64.b64decode(fields[1], validate=True)})
        except ValueError:
            continue
    return found


def handle_name(algorithm, application, user):
    """The file name `ssh-keygen -K` gives this key, so importing it again finds it."""
    suffix = "_".join(part for part in (application, user) if part)
    return "id_" + SSH_ALGORITHMS[algorithm] + "_rk" + ("_" + suffix if suffix else "")


def name_user(name, key_type, application):
    """The FIDO2 user ID `ssh-keygen -K` put in a copy's file name, or ""."""
    prefix = "id_" + SSH_ALGORITHMS.get(key_type, "") + "_rk"
    if not key_type or not name.startswith(prefix):
        return ""
    rest = name[len(prefix):]
    app = application[4:] if application.startswith("ssh:") else application
    if app:
        if not rest.startswith("_" + app):
            return ""
        rest = rest[len(app) + 1:]
    return rest[1:] if rest.startswith("_") else ""


def create_problem(options):
    """Why a new resident key's options can't be used ("" when they can). Checked
    before the key is touched, so nothing half-made stays on it."""
    algorithm = options.get("algorithm")
    application = options.get("application")
    user = options.get("user")
    comment = options.get("comment")
    if algorithm not in SSH_ALGORITHMS:
        return "algorithm"
    if not isinstance(application, str) or (application and (not CREATE_APPLICATION.fullmatch(application)
                                                             or ".." in application)):
        return "application"
    if not isinstance(user, str) or (user and (not CREATE_USER.fullmatch(user) or ".." in user)):
        return "user"
    # ssh-keygen -K would skip a handle named like a public half.
    if handle_name(algorithm, application, user).endswith(".pub"):
        return "pub-name"
    # The .pub file carries the comment; keep it plain ASCII.
    if not isinstance(comment, str) or len(comment) > 128 or not all(" " <= c <= "~" for c in comment):
        return "comment"
    if not isinstance(options.get("verify"), bool) or not isinstance(options.get("touch"), bool):
        return "flags"
    return ""


def create_command(path, options):
    command = ["ssh-keygen", "-t", options["algorithm"], "-O", "resident",
               "-O", "application=ssh:" + options["application"]]
    if options["user"]:
        command += ["-O", "user=" + options["user"]]
    if options["verify"]:
        command += ["-O", "verify-required"]
    if not options["touch"]:
        command += ["-O", "no-touch-required"]
    return command + ["-C", options["comment"], "-N", "", "-f", path]


def git_remote(application):
    """(login, host, port or "") for an application naming a git host, or None."""
    if not application.startswith("ssh:"):
        return None
    match = GIT_APPLICATION.fullmatch(application[4:])
    if not match:
        return None
    host, port = match["host"].lower(), match["port"]
    if port is not None and not 1 <= int(port) <= 65535:
        return None
    if host not in GIT_HOSTS and not any("git" in label for label in host.split(".")[:-1]):
        return None
    return match["login"] or "git", host, str(int(port)) if port else ""


def drop_in_text(names, remote, minutes=CONTROL_PERSIST_MINUTES):
    """The drop-in for <remote>'s keys. With 0 minutes, multiplexing is off
    explicitly (ControlMaster no alone could still reuse a master at an
    inherited ControlPath). None leaves the Control lines out."""
    login, host, port = remote
    lines = [DROP_IN_MARKER, "Host " + host, "    User " + login]
    if port:
        lines.append("    Port " + port)
    lines += [IDENTITY + name for name in sorted(names)]
    lines += ["    IdentitiesOnly yes", "    IdentityAgent none"]
    if minutes:
        lines += ["    ControlMaster auto", "    ControlPath ~/.ssh/" + CONTROL_DIR + "/%C",
                  "    ControlPersist " + str(minutes) + "m"]
    elif minutes is not None:
        lines += ["    ControlMaster no", "    ControlPath none", "    ControlPersist no"]
    return "\n".join(lines) + "\n"


def valid_minutes(value):
    return type(value) is int and 0 <= value <= MAX_PERSIST_MINUTES


def parse_drop_in(text):
    """A drop-in this helper wrote: ("ours", names, remote, minutes); ("edited",
    …) when it was changed since; ("foreign", [], None, None) when it isn't one
    of ours. minutes is None for a drop-in without Control lines."""
    lines = text.splitlines()
    if not lines or lines[0] != DROP_IN_MARKER:
        return "foreign", [], None, None
    login = host = port = ""
    names = []
    minutes = None
    for line in lines[1:]:
        if line.startswith("Host "):
            host = line[5:]
        elif line.startswith("    User "):
            login = line[9:]
        elif line.startswith("    Port "):
            port = line[9:]
        elif line.startswith(IDENTITY):
            names.append(line[len(IDENTITY):])
        elif line.startswith("    ControlPersist "):
            value = line[len("    ControlPersist "):]
            match = re.fullmatch(r"([1-9][0-9]{0,3})m", value)
            minutes = 0 if value == "no" else int(match[1]) if match else -1
    remote = (login, host, port)
    if (not host or not login or (minutes is not None and not valid_minutes(minutes))
            or drop_in_text(names, remote, minutes) != text):
        return "edited", names, remote, None
    return "ours", names, remote, minutes


def includes_drop_ins(config):
    """Whether an ssh config already includes config.d (home-manager's
    `includes = [ "~/.ssh/config.d/*.conf" ]` writes "Include ~/.ssh/config.d/*.conf")."""
    return any(re.match(r"\s*include\s+\S*config\.d/", line, re.IGNORECASE) for line in config.splitlines())


class SshMixin:
    """Session methods for resident SSH keys (see session.Session)."""

    def ssh_keys(self):
        try:
            names = os.listdir(self.paths.ssh)
        except OSError:
            return []
        return sorted(n for n in names if RESIDENT.match(n) and not n.endswith(".pub"))

    def read_ssh(self, name, follow=False):
        """A small file under ~/.ssh, as text; never through a symbolic link unless
        <follow> (~/.ssh/config, which home-manager links to the Nix store)."""
        flags = os.O_RDONLY | (0 if follow else os.O_NOFOLLOW)
        fd = os.open(os.path.join(self.paths.ssh, name), flags)
        with os.fdopen(fd, "rb") as f:
            data = f.read(SSH_FILE_LIMIT + 1)
        if len(data) > SSH_FILE_LIMIT:
            raise ValueError("%s is too large" % name)
        return data.decode("ascii")

    def ssh_public(self, name):
        try:
            return parse_public(self.read_ssh(name + ".pub"))
        except (OSError, ValueError, UnicodeError):
            return None

    def ssh_config_text(self):
        try:
            return self.read_ssh("config", follow=True)
        except FileNotFoundError:
            return ""
        except (OSError, ValueError, UnicodeError):
            return None

    def drop_in(self, host):
        """What ~/.ssh/config.d/<host>.conf is: ("missing", [], None, None) or parse_drop_in()."""
        try:
            text = self.read_ssh(os.path.join("config.d", host + ".conf"))
        except FileNotFoundError:
            return "missing", [], None, None
        except (OSError, ValueError, UnicodeError):
            return "foreign", [], None, None
        return parse_drop_in(text)

    def ssh_entries(self):
        """The resident keys in ~/.ssh, with the git host their application names
        and whether its drop-in uses them: hostState "on", "off", "edited" (the
        drop-in changed by hand) or "foreign" (a file this helper didn't write),
        and the minutes it keeps connections to that host for (0 when none)."""
        config = self.ssh_config_text()
        included = config is not None and includes_drop_ins(config)
        entries = []
        for name in self.ssh_keys():
            public = self.ssh_public(name)
            application = public["application"] if public else ""
            remote = git_remote(application)
            host = remote[1] if remote else ""
            state = ""
            minutes = CONTROL_PERSIST_MINUTES
            if remote:
                kind, names, _, found = self.drop_in(host)
                state = {"missing": "off", "edited": "edited", "foreign": "foreign"}.get(kind)
                if kind == "ours":
                    state = "on" if name in names and included else "off"
                    minutes = found or 0
            try:
                public_text = self.read_ssh(name + ".pub").strip() if public else ""
            except (OSError, ValueError, UnicodeError):
                public_text = ""
            try:
                encrypted = parse_handle(self.read_ssh(name))["encrypted"]
            except (OSError, ValueError, UnicodeError):
                encrypted = False
            entries.append({
                "name": name,
                "application": application,
                "type": public["type"] if public else "",
                "user": name_user(name, public["type"], application) if public else "",
                "fingerprint": fingerprint(public["blob"]) if public else "",
                "publicKey": public_text,
                "encrypted": encrypted,
                "host": host,
                "hostState": state,
                "persistMinutes": minutes,
            })
        return entries

    def ssh_defaults(self):
        """Suggestions for a new resident key: a random user ID (so keys for the
        same application don't replace each other on the key) and a comment."""
        hostname = re.sub(r"[^A-Za-z0-9._-]", "", socket.gethostname()) or "localhost"
        user = re.sub(r"[^A-Za-z0-9._-]", "", self.user) or "user"
        return {"user": secrets.token_hex(8), "comment": user + "@" + hostname}

    def ssh_include_state(self):
        """"ok" when ~/.ssh/config includes config.d (or there is none yet, and one will
        be written), "link" when it is a symbolic link without the Include."""
        text = self.ssh_config_text()
        if text is not None and includes_drop_ins(text):
            return "ok"
        if os.path.islink(os.path.join(self.paths.ssh, "config")):
            return "link"
        return "ok"

    def plan_host(self, name, remote, enable, minutes=None):
        """The change to remote's drop-in that adds or takes out <name>: (path,
        text, or None to delete it), or None when nothing changes. <minutes>
        sets the host's connection reuse; otherwise the drop-in keeps its own.
        Raises SshConfigError when the drop-in isn't the helper's to change."""
        host = remote[1]
        kind, names, current, kept = self.drop_in(host)
        path = os.path.join(self.paths.ssh, "config.d", host + ".conf")
        minutes = kept or CONTROL_PERSIST_MINUTES if minutes is None else minutes
        if not enable:
            if kind == "ours" and name in names:
                rest = [n for n in names if n != name]
                return path, drop_in_text(rest, current, minutes) if rest else None
            if kind == "edited" and name in names:
                raise SshConfigError("ssh-config-edited", "~/.ssh/config.d/" + host + ".conf")
            return None
        if kind == "foreign":
            raise SshConfigError("ssh-config-foreign", "~/.ssh/config.d/" + host + ".conf")
        if kind == "edited":
            raise SshConfigError("ssh-config-edited", "~/.ssh/config.d/" + host + ".conf")
        if kind == "ours" and tuple(current) != tuple(remote):
            # Another key names the same host with another login or port.
            raise SshConfigError("ssh-config-conflict", host)
        text = drop_in_text(sorted(set(names) | {name}), remote, minutes)
        if kind == "ours" and name in names and text == drop_in_text(names, current, kept):
            return None
        return path, text

    def apply_host(self, change):
        if change is None:
            return
        path, text = change
        if text is None:
            if os.path.lexists(path):
                os.unlink(path)
            return
        directory = os.path.dirname(path)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        if os.path.islink(directory) or not os.path.isdir(directory):
            raise SshConfigError("ssh-config-foreign", "~/.ssh/config.d")
        if "    ControlMaster auto\n" in text:
            # The master connections' sockets: private, as ssh requires.
            control = os.path.join(self.paths.ssh, CONTROL_DIR)
            os.makedirs(control, mode=0o700, exist_ok=True)
            if os.path.islink(control) or not os.path.isdir(control):
                raise SshConfigError("ssh-config-foreign", "~/.ssh/" + CONTROL_DIR)
            os.chmod(control, 0o700)
        replace_file(path, text, 0o600)

    def ensure_include(self):
        """Puts "Include config.d/*.conf" at the top of ~/.ssh/config, where it
        applies to every host, unless the file includes config.d already. A
        symbolic link (home-manager's) is never written to."""
        path = os.path.join(self.paths.ssh, "config")
        text = self.ssh_config_text()
        if text is not None and includes_drop_ins(text):
            return
        if os.path.islink(path):
            raise SshConfigError("ssh-config-link", "~/.ssh/config")
        if text is None:
            raise SshConfigError("ssh-config-foreign", "~/.ssh/config")
        mode = os.stat(path).st_mode & 0o777 if os.path.exists(path) else 0o600
        replace_file(path, SSH_INCLUDE + "\n" + ("\n" + text if text else ""), mode)

    def askpass_env(self, sock_path):
        env = dict(os.environ)
        env.update({"SSH_ASKPASS": self.askpass_command, "SSH_ASKPASS_REQUIRE": "force", ASKPASS_ENV: sock_path})
        env.setdefault("DISPLAY", ":0")
        return env

    async def ssh_import(self, pin):
        op = "ssh.import"
        if not self.devices:
            self.fail(op, "no-device")
            return
        workdir = tempfile.mkdtemp(prefix="noctalia-security-hw-", dir=self.paths.runtime)
        server = None
        try:
            sock_path = os.path.join(workdir, "askpass")
            server = await serve_pin(sock_path, pin)
            self.emit({"type": "busy", "op": op, "stage": "touch"})
            result = await self.runner.run(["ssh-keygen", "-K", "-N", ""], env=self.askpass_env(sock_path),
                                           cwd=workdir, timeout=TOUCH_TIMEOUT_S)
            found = sorted(n for n in os.listdir(workdir) if RESIDENT.match(n))
            if result.code != 0 and not found:
                code = "timeout" if result.err == "timeout" else fido_error(result.err, pin)
                log("ssh-keygen -K failed:", last_line(result.err))
                self.fail(op, code, last_line(result.err))
                # The key may have been pulled out, or its PIN retries changed.
                await self.refresh()
                return
            imported, skipped = self.install_ssh_keys(workdir, found)
            if not imported and not skipped:
                self.fail(op, "ssh-none")
                return
            self.emit({"type": "done", "op": op, "imported": imported, "skipped": skipped})
            await self.emit_state()
        finally:
            if server is not None:
                server.close()
            shutil.rmtree(workdir, ignore_errors=True)

    def host_change(self, name, enable):
        """plan_host() for the git host <name>'s application names, if any."""
        public = self.ssh_public(name)
        remote = git_remote(public["application"]) if public else None
        return self.plan_host(name, remote, enable) if remote else None

    def unlink_pair(self, name):
        for n in (name, name + ".pub"):
            path = os.path.join(self.paths.ssh, n)
            if os.path.lexists(path):
                os.unlink(path)

    async def ssh_remove(self, name):
        """Deletes one downloaded key (and its .pub) from ~/.ssh, and its line in
        the drop-in of its git host; only names ssh_keys() lists. The key itself
        stays on the security key."""
        op = "ssh.remove"
        if name not in self.ssh_keys():
            self.fail(op, "remove-failed", name)
            return
        try:
            change = self.host_change(name, False)
        except SshConfigError as e:
            self.fail(op, e.code, e.detail)
            return
        try:
            self.unlink_pair(name)
            self.apply_host(change)
        except (OSError, SshConfigError) as e:
            self.fail(op, "remove-failed", str(e))
            await self.emit_state()
            return
        self.emit({"type": "done", "op": op, "name": name})
        await self.emit_state()

    async def ssh_create(self, options, pin):
        """Makes a resident key on the security key (ssh-keygen -O resident), in
        a private folder, then copies its pair into ~/.ssh under the name
        `ssh-keygen -K` would give it, never over a file already there. A key
        with the same application and user ID on the security key is replaced
        only with "replace": the first try reports "ssh-exists"."""
        op = "ssh.create"
        problem = create_problem(options)
        if problem:
            self.fail(op, "ssh-invalid", problem)
            return
        if not self.devices:
            self.fail(op, "no-device")
            return
        name = handle_name(options["algorithm"], options["application"], options["user"])
        if any(os.path.lexists(os.path.join(self.paths.ssh, n)) for n in (name, name + ".pub")):
            self.fail(op, "ssh-file-exists", "~/.ssh/" + name)
            return
        workdir = tempfile.mkdtemp(prefix="noctalia-security-hw-", dir=self.paths.runtime)
        server = None
        try:
            sock_path = os.path.join(workdir, "askpass")
            server = await serve_pin(sock_path, pin)
            self.emit({"type": "busy", "op": op, "stage": "touch"})
            # ssh-keygen asks on stdin before replacing a key on the security key.
            result = await self.runner.run(create_command(os.path.join(workdir, name), options),
                                           stdin="y\n" if options.get("replace") is True else "n\n",
                                           env=self.askpass_env(sock_path), cwd=workdir, timeout=CREATE_TIMEOUT_S)
            made = all(os.path.exists(os.path.join(workdir, n)) for n in (name, name + ".pub"))
            if result.code != 0 or not made:
                if "Overwrite key in token" in result.out + result.err:
                    self.fail(op, "ssh-exists", "ssh:" + options["application"])
                    return
                code = "timeout" if result.err == "timeout" else fido_error(result.err, pin)
                log("ssh-keygen failed:", last_line(result.err))
                self.fail(op, code, last_line(result.err))
                await self.refresh()
                return
            imported, _ = self.install_ssh_keys(workdir, [name])
            if not imported:
                self.fail(op, "ssh-file-exists", "~/.ssh/" + name)
                return
            public = self.ssh_public(name)
            remote = git_remote(public["application"]) if public else None
            self.emit({"type": "done", "op": op, "name": name, "host": remote[1] if remote else "",
                       "publicKey": self.read_ssh(name + ".pub").strip()})
            await self.emit_state()
        finally:
            if server is not None:
                server.close()
            shutil.rmtree(workdir, ignore_errors=True)

    async def ssh_delete(self, name, pin):
        """Deletes the resident key behind ~/.ssh/<name> from the security key,
        for good, then the copy and its drop-in line. Only the exact credential
        of that copy (its key handle) is deleted: a copy of a key replaced since,
        or made on another security key, deletes nothing."""
        op = "ssh.delete"
        if name not in self.ssh_keys():
            self.fail(op, "remove-failed", name)
            return
        if not self.devices:
            self.fail(op, "no-device")
            return
        try:
            handle = parse_handle(self.read_ssh(name))
        except (OSError, ValueError, UnicodeError) as e:
            self.fail(op, "ssh-damaged", str(e))
            return
        public = self.ssh_public(name)
        if public is None or handle["blob"] != public["blob"]:
            self.fail(op, "ssh-damaged", "~/.ssh/" + name)
            return
        if handle["encrypted"]:
            self.fail(op, "ssh-encrypted", "~/.ssh/" + name)
            return
        # Checked before anything is deleted, so nothing is left half done.
        try:
            change = self.host_change(name, False)
        except SshConfigError as e:
            self.fail(op, e.code, e.detail)
            return
        device = self.devices[0]["path"]
        self.emit({"type": "busy", "op": op, "stage": "pin"})
        # Without a terminal fido2-token reads the PIN from stdin, once per run.
        listing = await self.runner.run(["fido2-token", "-L", "-k", public["application"], device],
                                        stdin=pin + "\n", timeout=AUTH_TIMEOUT_S)
        if listing.code != 0 and "NO_CREDENTIALS" not in listing.err:
            code = "timeout" if listing.err == "timeout" else fido_error(listing.err, pin)
            log("fido2-token -L -k failed:", last_line(listing.err))
            self.fail(op, code, last_line(listing.err))
            await self.refresh()
            return
        matches = [c for c in token_credentials(listing.out) if c["raw"] == handle["credential"]]
        if len(matches) != 1:
            self.fail(op, "ssh-not-on-key", "~/.ssh/" + name)
            return
        result = await self.runner.run(["fido2-token", "-D", "-i", matches[0]["id"], device],
                                       stdin=pin + "\n", timeout=AUTH_TIMEOUT_S)
        if result.code != 0:
            code = "timeout" if result.err == "timeout" else fido_error(result.err, pin)
            log("fido2-token -D failed:", last_line(result.err))
            self.fail(op, code, last_line(result.err))
            await self.refresh()
            return
        # The key is gone from the security key: its copy no longer works.
        try:
            self.unlink_pair(name)
            self.apply_host(change)
        except (OSError, SshConfigError) as e:
            log("cleaning up after deleting %s failed: %s" % (name, e))
        self.emit({"type": "done", "op": op, "name": name})
        await self.emit_state()

    async def ssh_host(self, name, enable, minutes=None):
        """Adds <name> to the drop-in of the git host its application names, or
        takes it out (the drop-in goes with its last key); the drop-in uses the
        keys for that host without the SSH agent. <minutes>, when given, sets
        the host's connection reuse too."""
        op = "ssh.host"
        if minutes is not None and not valid_minutes(minutes):
            self.fail(op, "ssh-invalid", "minutes")
            return
        entry = next((e for e in self.ssh_entries() if e["name"] == name), None)
        if entry is None or not entry["host"]:
            self.fail(op, "generic", name)
            return
        try:
            change = self.plan_host(name, git_remote(entry["application"]), enable, minutes)
            if enable:
                self.ensure_include()
            self.apply_host(change)
        except SshConfigError as e:
            self.fail(op, e.code, e.detail)
            return
        except OSError as e:
            self.fail(op, "write-failed", str(e))
            await self.emit_state()
            return
        self.emit({"type": "done", "op": op, "name": name, "host": entry["host"], "enabled": enable})
        await self.emit_state()

    async def ssh_persist(self, name, minutes):
        """Sets how long connections to the git host of <name>'s drop-in are
        reused: 0 authenticates each one, up to MAX_PERSIST_MINUTES keeps the
        authenticated master that long. The drop-in has to use the key already."""
        op = "ssh.persist"
        if not valid_minutes(minutes):
            self.fail(op, "ssh-invalid", "minutes")
            return
        entry = next((e for e in self.ssh_entries() if e["name"] == name), None)
        if entry is None or entry["hostState"] != "on":
            self.fail(op, "generic", name)
            return
        try:
            self.apply_host(self.plan_host(name, git_remote(entry["application"]), True, minutes))
        except SshConfigError as e:
            self.fail(op, e.code, e.detail)
            return
        except OSError as e:
            self.fail(op, "write-failed", str(e))
            await self.emit_state()
            return
        self.emit({"type": "done", "op": op, "name": name, "host": entry["host"], "minutes": minutes})
        await self.emit_state()

    def install_ssh_keys(self, workdir, names):
        """Copies complete downloaded pairs into ~/.ssh (0600/0644), never over an
        existing file, either half of a pair included; a pair that fails halfway
        is taken out again."""
        os.makedirs(self.paths.ssh, mode=0o700, exist_ok=True)
        imported = []
        skipped = []
        for name in names:
            if name.endswith(".pub"):
                continue
            pair = [name, name + ".pub"]
            if not all(os.path.isfile(os.path.join(workdir, n)) for n in pair):
                continue
            if any(os.path.lexists(os.path.join(self.paths.ssh, n)) for n in pair):
                skipped.append(name)
                continue
            written = []
            try:
                for n, mode in zip(pair, (0o600, 0o644)):
                    target = os.path.join(self.paths.ssh, n)
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
                    written.append(target)
                    with os.fdopen(fd, "wb") as out, open(os.path.join(workdir, n), "rb") as source:
                        shutil.copyfileobj(source, out)
                    os.chmod(target, mode)
            except OSError as e:
                log("could not copy %s: %s" % (name, e))
                for target in written:
                    try:
                        os.unlink(target)
                    except OSError:
                        pass
                skipped.append(name)
                continue
            imported.append(name)
        return imported, skipped
