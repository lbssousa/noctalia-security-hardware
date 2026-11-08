import asyncio
import base64
import json
import os
import pathlib
import socket
import stat
import sys
import tempfile
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from noctalia_security_hw import cli, common, fido, gpg, pin, session, ssh  # noqa: E402

# One namespace, as when this was a single file.
helper = types.SimpleNamespace(**{k: v for m in (common, fido, gpg, pin, ssh, session) for k, v in vars(m).items()
                                  if not k.startswith("_")})
HELPER = ROOT / "noctalia-security-hw"
FINGERPRINT = {"available": False, "devices": [], "default": ""}

DEVICES = "/dev/hidraw1: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)\n"
INFO = """proto: 0x02
version strings: U2F_V2, FIDO_2_0, FIDO_2_1_PRE
options: rk, up, noplat, clientPin, credentialMgmtPreview
pin retries: 8
"""
CARD = """Reader:1050:0407:X:0:AID:D2760001240100000006203732350000:openpgp-card:
vendor:0006:Yubico:
serial:20373235:
name:Ada:Lovelace:
url:https\\x3a//keys.example/ada.asc:
fpr:AAAABBBBCCCCDDDDEEEEFFFF0000111122223333:1E5A0912DCA511B6FF009497815B06463B9F3121::
"""
PUBLIC = """pub:u:255:22:B10712C404063D38:1767115511:::u:::scESC:::#:::23::0:
fpr:::::::::PRIMARY0000000000000000000000000000000000:
"""
CRED1 = "HANDLEONE111,pubkey1,es256,+presence"
CRED2 = "HANDLETWO222,pubkey2,es256,+presence"

# Resident SSH keys, built the way ssh-keygen writes them (no key needed).
ED25519_SK = "sk-ssh-ed25519@openssh.com"


def ssh_str(data):
    return len(data).to_bytes(4, "big") + data


def sk_blob(application, point=b"\x01" * 32):
    return ssh_str(ED25519_SK.encode()) + ssh_str(point) + ssh_str(application.encode())


def pub_text(application, point=b"\x01" * 32):
    return "%s %s ada@host\n" % (ED25519_SK, base64.b64encode(sk_blob(application, point)).decode())


def handle_text(application, credential, point=b"\x01" * 32, cipher=b"none"):
    private = b"\0\0\0\7" * 2 + ssh_str(ED25519_SK.encode()) + ssh_str(point) + ssh_str(application.encode())
    private += b"\x01" + ssh_str(credential) + ssh_str(b"") + ssh_str(b"ada@host")
    private += bytes(range(1, 1 + (-len(private) % 8)))
    data = b"openssh-key-v1\0" + ssh_str(cipher) + ssh_str(b"none" if cipher == b"none" else b"bcrypt")
    data += ssh_str(b"") + b"\0\0\0\1" + ssh_str(sk_blob(application, point)) + ssh_str(private)
    return ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.b64encode(data).decode()
            + "\n-----END OPENSSH PRIVATE KEY-----\n")


def token_listing(*credentials):
    return "".join("%02d: %s (null) dXNlcg== eddsa uvopt+id\n" % (i, base64.b64encode(c).decode())
                   for i, c in enumerate(credentials))


CREATE = {"algorithm": "ed25519-sk", "application": "github.com", "user": "0123456789abcdef",
          "verify": True, "touch": True, "comment": "ada@host"}


class FakeRunner:
    """Answers from a table keyed by the program's first two words; records every run."""

    def __init__(self):
        self.calls = []
        self.answers = {
            ("fido2-token", "-L"): helper.Result(0, DEVICES),
            ("fido2-token", "-I"): helper.Result(0, INFO),
            ("gpg", "--card-status"): helper.Result(0, CARD),
            ("gpg", "--list-keys"): helper.Result(0, PUBLIC),
            ("gpg", "--list-secret-keys"): helper.Result(0, "sec:u:255\n"),
            ("fido2-assert", "-G"): helper.Result(1, "", "FIDO_ERR_NO_CREDENTIALS"),
        }
        self.cancelled = False
        self.hook = None

    async def run(self, args, stdin=None, env=None, cwd=None, timeout=None):
        self.calls.append((list(args), stdin, env, cwd))
        if self.hook:
            result = await self.hook(args, stdin, env, cwd)
            if result is not None:
                return result
        return self.answers.get(tuple(args[:2]), helper.Result(0))

    def cancel(self):
        self.cancelled = True

    def ran(self, *prefix):
        return [c for c in self.calls if tuple(c[0][:len(prefix)]) == prefix]


class SessionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name)
        self.home = root / "home"
        self.pam = root / "pam.d"
        self.home.mkdir()
        self.pam.mkdir()
        (self.pam / "sudo").write_text("auth sufficient pam_u2f.so cue\nauth include system-auth\n")
        (self.pam / "polkit-1").write_text("auth include system-auth\n")
        self.paths = helper.Paths(home=str(self.home), config=str(self.home / ".config"),
                                  pam_dirs=[str(self.pam)], runtime=str(root))
        self.runner = FakeRunner()
        self.events = []
        self.session = helper.Session(self.runner, self.events.append, self.paths, "ada", "/askpass",
                                      fingerprint=lambda: FINGERPRINT)

    def tearDown(self):
        self.tmp.cleanup()

    def run_op(self, coroutine):
        asyncio.run(coroutine)

    def last(self, kind):
        return [e for e in self.events if e["type"] == kind][-1]

    def authfile(self):
        return pathlib.Path(self.paths.authfile)

    # -- parsers ---------------------------------------------------------

    def test_parse_devices_and_info(self):
        self.assertEqual(helper.parse_devices(DEVICES + "garbage\n"),
                         [{"path": "/dev/hidraw1", "name": "Yubico YubiKey OTP+FIDO+CCID"}])
        self.assertEqual(helper.parse_info(INFO), {"rk": True, "clientPin": True, "pinRetries": 8})
        no_pin = helper.parse_info("options: up, noclientPin\n")
        self.assertEqual((no_pin["rk"], no_pin["clientPin"], no_pin["pinRetries"]), (False, False, -1))

    def test_parse_card(self):
        card = helper.parse_card(CARD)
        self.assertEqual(card["holder"], "Ada Lovelace")
        self.assertEqual(card["url"], "https://keys.example/ada.asc")
        self.assertEqual(card["fingerprints"], ["AAAABBBBCCCCDDDDEEEEFFFF0000111122223333",
                                                "1E5A0912DCA511B6FF009497815B06463B9F3121"])
        self.assertIsNone(helper.parse_card("Reader:1050:0407:X:0:AID:piv-only:\n"))
        self.assertIsNone(helper.parse_card(""))

    def test_pam_lines(self):
        self.assertEqual(helper.pam_u2f("auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2\n"),
                         {"u2f": True, "authfile": "/etc/fido2/fido2", "pin": False})
        self.assertEqual(helper.pam_u2f("#auth sufficient pam_u2f.so\nauth include system-auth\n"),
                         {"u2f": False, "authfile": "", "pin": False})
        self.assertTrue(helper.pam_u2f("auth sufficient pam_u2f.so cue pinverification=1 userpresence=1\n")["pin"])
        self.assertFalse(helper.pam_u2f("auth sufficient pam_u2f.so cue pinverification=0\n")["pin"])

    def test_merge_skips_known_key_handles(self):
        self.assertEqual(helper.merge_credentials([CRED1], ["HANDLEONE111,other,es256,+presence", CRED2]),
                         [CRED1, CRED2])

    def test_errors_map_to_codes(self):
        self.assertEqual(helper.fido_error("error: fido_dev_make_cred (49) FIDO_ERR_PIN_INVALID"), "pin-invalid")
        self.assertEqual(helper.fido_error("error: fido_dev_make_cred (50) FIDO_ERR_PIN_BLOCKED"), "pin-blocked")
        self.assertEqual(helper.fido_error("error: fido_dev_make_cred (47) FIDO_ERR_ACTION_TIMEOUT"), "timeout")
        self.assertEqual(helper.fido_error("Unable to load resident keys: PIN incorrect"), "pin-invalid")
        self.assertEqual(helper.fido_error("No keys to download"), "ssh-none")
        self.assertEqual(helper.fido_error("something odd"), "generic")
        empty = "Enter PIN for /dev/hidraw1: error: fido_dev_make_cred (-7) FIDO_ERR_INVALID_ARGUMENT"
        self.assertEqual(helper.fido_error(empty), "pin-required")
        self.assertEqual(helper.fido_error(empty, "1234"), "generic")

    # -- state -----------------------------------------------------------

    def test_refresh_reports_everything(self):
        self.authfile().parent.mkdir(parents=True)
        self.authfile().write_text("bob:BOBKEY,p,es256,+presence\nada:%s\n" % CRED1)
        (self.home / ".ssh").mkdir()
        (self.home / ".ssh" / "id_ed25519_sk_rk").write_text("k")
        (self.home / ".ssh" / "id_ed25519_sk_rk.pub").write_text("k")
        self.run_op(self.session.refresh())
        state = self.last("state")
        self.assertEqual(state["devices"][0]["name"], "Yubico YubiKey OTP+FIDO+CCID")
        self.assertTrue(state["devices"][0]["rk"])
        self.assertEqual(state["credentials"], [{"handle": "HANDLEONE111", "label": "HANDLEONE1", "unused": False}])
        self.assertEqual(state["target"]["kind"], "own")
        self.assertEqual(state["card"]["serial"], "20373235")
        self.assertEqual((state["keyState"], state["trusted"]), ("ready", True))
        self.assertEqual(state["sshKeys"], [{"name": "id_ed25519_sk_rk", "application": "", "type": "", "user": "",
                                             "fingerprint": "", "publicKey": "", "encrypted": False, "host": "",
                                             "hostState": "", "persistMinutes": 0}])
        self.assertEqual(len(state["sshDefaults"]["user"]), 16)
        self.assertEqual(state["sshDefaults"]["comment"].split("@")[0], "ada")
        self.assertEqual(state["otherCount"], 0)
        self.assertEqual(state["fingerprint"], FINGERPRINT)
        self.assertEqual((state["sshInclude"], state["testService"]), ("ok", ""))

    def test_key_states(self):
        self.runner.answers[("gpg", "--list-secret-keys")] = helper.Result(2, "")
        self.run_op(self.session.refresh())
        self.assertEqual(self.last("state")["keyState"], "public")
        self.runner.answers[("gpg", "--list-keys")] = helper.Result(2, "")
        self.run_op(self.session.refresh())
        self.assertEqual(self.last("state")["keyState"], "missing")
        self.runner.answers[("gpg", "--card-status")] = helper.Result(2, "")
        self.run_op(self.session.refresh())
        self.assertIsNone(self.last("state")["card"])
        self.assertEqual(self.last("state")["keyState"], "none")

    def test_other_authfile_is_counted(self):
        shared = pathlib.Path(self.tmp.name) / "fido2"
        shared.write_text("ada:%s:%s\nbob:X,y,es256,+presence\n" % (CRED1, CRED2))
        (self.pam / "sudo").write_text("auth sufficient pam_u2f.so cue authfile=%s\n" % shared)
        self.run_op(self.session.refresh())
        self.assertEqual(self.last("state")["otherCount"], 2)
        self.assertEqual(self.last("state")["target"]["kind"], "other-file")

    def test_probe_lists_device_paths(self):
        self.run_op(self.session.probe())
        self.assertEqual(self.last("probe")["devices"], ["/dev/hidraw1"])

    # -- FIDO2 -----------------------------------------------------------

    def registered(self):
        self.run_op(self.session.refresh())
        self.events.clear()

    def test_register_writes_a_private_authfile(self):
        self.registered()
        self.runner.answers[("pamu2fcfg", "-u")] = helper.Result(0, "ada:%s\n" % CRED1)
        self.run_op(self.session.fido_register("1234"))
        args, stdin, _, _ = self.runner.ran("pamu2fcfg")[0]
        self.assertEqual((args, stdin), (["pamu2fcfg", "-u", "ada"], "1234\n"))
        self.assertEqual(self.events[0], {"type": "busy", "op": "fido.register", "stage": "touch"})
        self.assertEqual(self.last("done")["op"], "fido.register")
        self.assertEqual(self.authfile().read_text(), "ada:%s\n" % CRED1)
        self.assertEqual(stat.S_IMODE(self.authfile().stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.authfile().parent.stat().st_mode), 0o700)

    def test_register_appends_and_keeps_other_users(self):
        self.authfile().parent.mkdir(parents=True)
        self.authfile().write_text("bob:B,p,es256,+presence\nada:%s\n" % CRED1)
        self.registered()
        self.runner.answers[("pamu2fcfg", "-u")] = helper.Result(0, "ada:%s\n" % CRED2)
        self.run_op(self.session.fido_register(""))
        self.assertIsNone(self.runner.ran("pamu2fcfg")[0][1])
        self.assertEqual(self.authfile().read_text(), "bob:B,p,es256,+presence\nada:%s:%s\n" % (CRED1, CRED2))
        self.assertEqual(len(self.last("state")["credentials"]), 2)

    def test_register_refuses_the_same_key_without_a_touch(self):
        self.authfile().parent.mkdir(parents=True)
        self.authfile().write_text("ada:%s:%s\n" % (CRED1, CRED2))
        self.registered()
        self.runner.answers[("fido2-assert", "-G")] = helper.Result(0, "assertion")
        self.run_op(self.session.fido_register(""))
        self.assertEqual(self.last("error")["code"], "already-registered")
        self.assertEqual(self.runner.ran("pamu2fcfg"), [])
        args, stdin, _, _ = self.runner.ran("fido2-assert")[0]
        self.assertEqual(args, ["fido2-assert", "-G", "-t", "up=false", "/dev/hidraw1"])
        self.assertEqual(stdin.splitlines()[1:], ["pam://" + socket.gethostname(), "HANDLEONE111"])

    def test_register_tries_every_credential_of_the_key(self):
        self.authfile().parent.mkdir(parents=True)
        self.authfile().write_text("ada:%s:%s\n" % (CRED1, CRED2))
        self.registered()
        self.runner.answers[("pamu2fcfg", "-u")] = helper.Result(0, "ada:NEWKEY333,p,es256,+presence\n")
        self.run_op(self.session.fido_register(""))
        self.assertEqual(len(self.runner.ran("fido2-assert")), 2)
        self.assertEqual(self.last("done")["op"], "fido.register")

    def assert_register_refused(self, kind):
        self.registered()
        self.assertEqual(self.session.fido_target()["kind"], kind)
        self.run_op(self.session.fido_register(""))
        self.assertEqual(self.last("error"), {"type": "error", "op": "fido.register", "code": "not-target",
                                              "detail": kind})
        self.assertEqual(self.runner.ran("pamu2fcfg"), [])
        self.assertFalse(self.authfile().exists())

    def test_register_refused_when_no_service_asks_for_a_key(self):
        (self.pam / "sudo").write_text("auth include system-auth\n")
        self.assert_register_refused("no-pam")

    def test_register_refused_for_a_file_the_helper_does_not_write(self):
        (self.pam / "sudo").write_text("auth sufficient pam_u2f.so cue authfile=/etc/elsewhere\n")
        self.assert_register_refused("other-file")
        self.assertEqual(self.session.fido_target()["path"], "/etc/elsewhere")

    def test_register_refused_when_the_services_read_different_files(self):
        (self.pam / "polkit-1").write_text("auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2\n")
        self.assert_register_refused("mixed")

    def test_old_keys_in_the_own_list_show_as_unused_and_can_go(self):
        self.authfile().parent.mkdir(parents=True)
        self.authfile().write_text("ada:%s\n" % CRED1)
        (self.pam / "sudo").write_text("auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2\n")
        self.run_op(self.session.refresh())
        self.assertEqual(self.last("state")["credentials"],
                         [{"handle": "HANDLEONE111", "label": "HANDLEONE1", "unused": True}])
        self.run_op(self.session.fido_remove("HANDLEONE111"))
        self.assertEqual(self.authfile().read_text(), "")

    def test_register_refuses_a_key_without_a_pin_when_pam_demands_one(self):
        (self.pam / "sudo").write_text("auth sufficient pam_u2f.so cue pinverification=1\n")
        self.runner.answers[("fido2-token", "-I")] = helper.Result(0, "options: up, noclientPin\n")
        self.registered()
        self.run_op(self.session.fido_register(""))
        self.assertEqual(self.last("error")["code"], "no-pin")
        self.assertEqual(self.runner.ran("pamu2fcfg"), [])
        self.run_op(self.session.refresh())
        self.assertTrue(self.last("state")["pinRequired"])

    def test_register_takes_a_key_without_a_pin_when_pam_demands_none(self):
        self.runner.answers[("fido2-token", "-I")] = helper.Result(0, "options: up, noclientPin\n")
        self.registered()
        self.runner.answers[("pamu2fcfg", "-u")] = helper.Result(0, "ada:%s\n" % CRED1)
        self.run_op(self.session.fido_register(""))
        self.assertEqual(self.last("done")["op"], "fido.register")
        self.assertFalse(self.last("state")["pinRequired"])

    def test_register_failure_reports_the_code(self):
        self.registered()
        self.runner.answers[("pamu2fcfg", "-u")] = helper.Result(1, "", "error: fido_dev_make_cred (49) FIDO_ERR_PIN_INVALID\n")
        self.run_op(self.session.fido_register("0000"))
        self.assertEqual(self.last("error")["code"], "pin-invalid")
        self.assertFalse(self.authfile().exists())

    def test_register_needs_a_key(self):
        self.runner.answers[("fido2-token", "-L")] = helper.Result(0, "")
        self.registered()
        self.run_op(self.session.fido_register(""))
        self.assertEqual(self.last("error")["code"], "no-device")
        self.assertEqual(self.runner.ran("pamu2fcfg"), [])

    def test_remove_drops_one_key_then_the_line(self):
        self.authfile().parent.mkdir(parents=True)
        self.authfile().write_text("ada:%s:%s\nbob:B,p,es256,+presence\n" % (CRED1, CRED2))
        self.registered()
        self.run_op(self.session.fido_remove("HANDLEONE111"))
        self.assertEqual(self.authfile().read_text(), "bob:B,p,es256,+presence\nada:%s\n" % CRED2)
        self.run_op(self.session.fido_remove("HANDLETWO222"))
        self.assertEqual(self.authfile().read_text(), "bob:B,p,es256,+presence\n")
        for handle in ("HANDLETWO222", "", "B"):
            self.events.clear()
            self.run_op(self.session.fido_remove(handle))
            self.assertEqual(self.last("error")["code"], "generic")
        self.assertEqual(self.authfile().read_text(), "bob:B,p,es256,+presence\n")

    def test_fido_test_runs_pamtester_on_the_test_service(self):
        self.registered()
        self.run_op(self.session.fido_test())
        self.assertEqual(self.last("error")["code"], "no-test-service")
        (self.pam / "noctalia-lock-u2f").write_text("auth required pam_u2f.so\n")
        self.run_op(self.session.fido_test())
        self.assertEqual(self.runner.ran("pamtester")[0][0], ["pamtester", "noctalia-lock-u2f", "ada", "authenticate"])
        self.assertEqual(self.last("done")["op"], "fido.test")
        self.runner.answers[("pamtester", "noctalia-lock-u2f")] = helper.Result(1, "", "Authentication failure")
        self.run_op(self.session.fido_test())
        self.assertEqual(self.last("error")["code"], "test-failed")
        self.run_op(self.session.refresh())
        self.assertEqual(self.last("state")["testService"], "noctalia-lock-u2f")

    # -- OpenPGP ---------------------------------------------------------

    def test_gpg_import_tries_the_card_url_then_the_keyservers(self):
        self.registered()
        self.runner.answers[("gpg", "--fetch-keys")] = helper.Result(2, "", "no data")
        self.run_op(self.session.gpg_import())
        self.assertEqual(self.runner.ran("gpg", "--fetch-keys")[0][0][2], "https://keys.example/ada.asc")
        self.assertEqual(self.runner.ran("gpg", "--recv-keys")[0][0][2], "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333")
        self.assertEqual(self.last("done")["op"], "gpg.import")
        self.runner.answers[("gpg", "--recv-keys")] = helper.Result(2, "", "no data")
        self.run_op(self.session.gpg_import())
        self.assertEqual(self.last("error")["code"], "import-failed")

    def test_gpg_trust_uses_the_primary_fingerprint(self):
        self.registered()
        self.run_op(self.session.gpg_trust())
        _, stdin, _, _ = self.runner.ran("gpg", "--import-ownertrust")[0]
        self.assertEqual(stdin, "PRIMARY0000000000000000000000000000000000:6:\n")
        self.assertEqual(self.last("done")["op"], "gpg.trust")

    def test_gpg_remove_takes_out_the_public_key_and_the_card_stubs(self):
        self.registered()
        self.runner.answers[("gpg", "--list-secret-keys")] = helper.Result(
            0, "sec:u:255:22:B10712C404063D38::::::::::D2760001240100000006203732350000:\n"
               "ssb:u:255:18:815B06463B9F3121::::::::::#:\n")
        self.run_op(self.session.gpg_remove())
        args = self.runner.ran("gpg", "--batch")[0][0]
        self.assertEqual(args, ["gpg", "--batch", "--yes", "--delete-secret-and-public-keys",
                                "PRIMARY0000000000000000000000000000000000"])
        self.assertEqual(self.last("done")["op"], "gpg.remove")

    def test_gpg_remove_never_touches_a_secret_kept_on_disk(self):
        self.registered()
        for listing in ("sec:u:255:22:B10712C404063D38::::::::::+:\n", "sec:u:255\n"):
            self.events.clear()
            self.runner.answers[("gpg", "--list-secret-keys")] = helper.Result(0, listing)
            self.run_op(self.session.gpg_remove())
            self.assertEqual(self.last("error")["code"], "secret-on-disk")
        self.assertEqual(self.runner.ran("gpg", "--batch"), [])

    def test_gpg_remove_without_secret_stubs_deletes_the_public_key(self):
        self.registered()
        self.runner.answers[("gpg", "--list-secret-keys")] = helper.Result(2, "")
        self.run_op(self.session.gpg_remove())
        self.assertEqual(self.runner.ran("gpg", "--batch")[0][0][3], "--delete-keys")

    # -- SSH -------------------------------------------------------------

    def test_ssh_remove_deletes_the_pair_and_only_listed_keys(self):
        ssh = self.home / ".ssh"
        ssh.mkdir()
        for name in ("id_ed25519_sk_rk_x", "id_ed25519_sk_rk_x.pub", "id_ed25519", "id_ed25519.pub"):
            (ssh / name).write_text("k")
        self.registered()
        self.run_op(self.session.ssh_remove("id_ed25519_sk_rk_x"))
        self.assertEqual(self.last("done"), {"type": "done", "op": "ssh.remove", "name": "id_ed25519_sk_rk_x"})
        for name in ("id_ed25519", "../.ssh/id_ed25519", "id_ed25519_sk_rk_x"):
            self.events.clear()
            self.run_op(self.session.ssh_remove(name))
            self.assertEqual(self.last("error")["code"], "remove-failed")
        self.assertEqual(sorted(os.listdir(ssh)), ["id_ed25519", "id_ed25519.pub"])


    def test_ssh_import_hands_the_pin_to_askpass_and_never_overwrites(self):
        (self.home / ".ssh").mkdir()
        (self.home / ".ssh" / "id_ed25519_sk_rk_old").write_text("mine")
        self.registered()
        seen = {}

        async def keygen(args, stdin, env, cwd):
            if args[0] != "ssh-keygen":
                return None
            seen["env"] = env
            seen["args"] = args
            # What our own askpass would do: ask the helper over its socket.
            reader, writer = await asyncio.open_unix_connection(env[helper.ASKPASS_ENV])
            writer.write(b"Enter PIN for authenticator: \n")
            await writer.drain()
            seen["pin"] = (await reader.readline()).decode().strip()
            writer.close()
            for name in ("id_ed25519_sk_rk", "id_ed25519_sk_rk_old"):
                pathlib.Path(cwd, name).write_text("key")
                pathlib.Path(cwd, name + ".pub").write_text("pub")
            return helper.Result(0)

        self.runner.hook = keygen
        self.run_op(self.session.ssh_import("4321"))
        self.assertEqual(seen["pin"], "4321")
        self.assertEqual(seen["args"], ["ssh-keygen", "-K", "-N", ""])
        self.assertEqual((seen["env"]["SSH_ASKPASS"], seen["env"]["SSH_ASKPASS_REQUIRE"]), ("/askpass", "force"))
        self.assertNotIn("4321", json.dumps(seen["env"]))
        done = self.last("done")
        self.assertEqual((done["imported"], done["skipped"]), (["id_ed25519_sk_rk"], ["id_ed25519_sk_rk_old"]))
        ssh = self.home / ".ssh"
        self.assertEqual((ssh / "id_ed25519_sk_rk_old").read_text(), "mine")
        self.assertEqual(stat.S_IMODE((ssh / "id_ed25519_sk_rk").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((ssh / "id_ed25519_sk_rk.pub").stat().st_mode), 0o644)
        # The private work folder is gone.
        self.assertEqual([n for n in os.listdir(self.tmp.name) if n.startswith("noctalia-security-hw-")], [])

    def test_askpass_mode_prints_the_pin_once(self):
        async def scenario():
            path = os.path.join(self.tmp.name, "askpass")
            server = await helper.serve_pin(path, "2468")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode) & 0o077, 0)
            env = dict(os.environ, **{helper.ASKPASS_ENV: path})
            outputs = []
            for _ in range(2):
                # As ssh-keygen runs it: the program, then the prompt alone.
                proc = await asyncio.create_subprocess_exec(
                    str(HELPER), "Enter PIN for authenticator: ",
                    env=env, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE)
                out, _ = await proc.communicate()
                outputs.append((proc.returncode, out.decode()))
            server.close()
            return outputs

        self.assertEqual(asyncio.run(scenario()), [(0, "2468\n"), (1, "")])

    def test_ssh_import_failure(self):
        self.registered()
        self.runner.answers[("ssh-keygen", "-K")] = helper.Result(255, "", "Unable to load resident keys: PIN incorrect")
        self.run_op(self.session.ssh_import("0000"))
        self.assertEqual(self.last("error")["code"], "pin-invalid")

    # -- SSH: new keys, deleting them, git hosts ---------------------------

    def ssh_key(self, name, application, credential=b"C" * 64, point=b"\x01" * 32, cipher=b"none"):
        ssh = self.home / ".ssh"
        ssh.mkdir(exist_ok=True)
        (ssh / name).write_text(handle_text(application, credential, point, cipher))
        (ssh / (name + ".pub")).write_text(pub_text(application, point))
        return ssh

    def test_parse_public_and_handle(self):
        public = helper.parse_public(pub_text("ssh:github.com"))
        self.assertEqual((public["type"], public["application"]), ("ed25519-sk", "ssh:github.com"))
        handle = helper.parse_handle(handle_text("ssh:github.com", b"K" * 48))
        self.assertEqual((handle["encrypted"], handle["credential"]), (False, b"K" * 48))
        self.assertEqual(handle["blob"], public["blob"])
        encrypted = helper.parse_handle(handle_text("ssh:github.com", b"K" * 48, cipher=b"aes256-ctr"))
        self.assertEqual((encrypted["encrypted"], encrypted["credential"]), (True, None))
        self.assertIsNone(helper.parse_public("ssh-ed25519 AAAA x"))
        with self.assertRaises(ValueError):
            helper.parse_handle("not a key")

    def test_git_remotes(self):
        self.assertEqual(helper.git_remote("ssh:github.com"), ("git", "github.com", ""))
        self.assertEqual(helper.git_remote("ssh:me@git.example.org:2222"), ("me", "git.example.org", "2222"))
        for application in ("ssh:", "ssh:work", "ssh:example.org", "ssh:github.com:99999", "github.com"):
            self.assertIsNone(helper.git_remote(application), application)

    def test_create_options_are_checked_before_the_key_is_touched(self):
        self.registered()
        bad = [{"comment": "café"}, {"comment": "a" * 129}, {"user": "work.pub"}, {"user": "a/b"},
               {"user": "a..b"}, {"application": "x/y"}, {"application": "", "user": "x.pub"},
               {"algorithm": "rsa"}, {"verify": "yes"}]
        for change in bad:
            self.events.clear()
            self.run_op(self.session.ssh_create(dict(CREATE, **change), "1234"))
            self.assertEqual(self.last("error")["code"], "ssh-invalid", change)
        self.assertEqual(self.runner.ran("ssh-keygen"), [])
        self.assertEqual(helper.create_problem(dict(CREATE, application="", user="")), "")

    def creating(self, seen, exists=False):
        async def keygen(args, stdin, env, cwd):
            if args[0] != "ssh-keygen":
                return None
            seen.setdefault("runs", []).append((args, stdin))
            reader, writer = await asyncio.open_unix_connection(env[helper.ASKPASS_ENV])
            writer.write(b"Enter PIN for ED25519-SK key: \n")
            await writer.drain()
            seen["pin"] = (await reader.readline()).decode().strip()
            writer.close()
            if exists and stdin != "y\n":
                return helper.Result(255, "A resident key scoped to 'ssh:github.com' with user id "
                                          "'0123456789abcdef' already exists.\nOverwrite key in token (y/n)? ",
                                     "Key enrollment failed: requested feature not supported")
            path = args[args.index("-f") + 1]
            pathlib.Path(path).write_text(handle_text("ssh:github.com", b"N" * 64))
            pathlib.Path(path + ".pub").write_text(pub_text("ssh:github.com"))
            return helper.Result(0)
        return keygen

    def test_create_makes_the_key_and_copies_it_in(self):
        self.registered()
        seen = {}
        self.runner.hook = self.creating(seen)
        self.run_op(self.session.ssh_create(dict(CREATE, touch=False), "4321"))
        args, stdin = seen["runs"][0]
        name = "id_ed25519_sk_rk_github.com_0123456789abcdef"
        self.assertEqual(args[:-1], ["ssh-keygen", "-t", "ed25519-sk", "-O", "resident",
                                     "-O", "application=ssh:github.com", "-O", "user=0123456789abcdef",
                                     "-O", "verify-required", "-O", "no-touch-required",
                                     "-C", "ada@host", "-N", "", "-f"])
        self.assertEqual(os.path.basename(args[-1]), name)
        self.assertEqual((stdin, seen["pin"]), ("n\n", "4321"))
        done = self.last("done")
        self.assertEqual((done["op"], done["name"], done["host"]), ("ssh.create", name, "github.com"))
        self.assertTrue(done["publicKey"].startswith(ED25519_SK + " "))
        ssh = self.home / ".ssh"
        self.assertEqual(stat.S_IMODE((ssh / name).stat().st_mode), 0o600)
        self.assertEqual([n for n in os.listdir(self.tmp.name) if n.startswith("noctalia-security-hw-")], [])

    def test_create_asks_before_replacing_a_key_on_the_security_key(self):
        self.registered()
        seen = {}
        self.runner.hook = self.creating(seen, exists=True)
        self.run_op(self.session.ssh_create(CREATE, "4321"))
        self.assertEqual(self.last("error")["code"], "ssh-exists")
        self.assertFalse((self.home / ".ssh").exists())
        self.run_op(self.session.ssh_create(dict(CREATE, replace=True), "4321"))
        self.assertEqual(seen["runs"][-1][1], "y\n")
        self.assertEqual(self.last("done")["op"], "ssh.create")

    def test_create_never_overwrites_a_file_in_ssh(self):
        self.registered()
        ssh = self.home / ".ssh"
        ssh.mkdir()
        (ssh / "id_ed25519_sk_rk_github.com_0123456789abcdef.pub").write_text("mine")
        self.run_op(self.session.ssh_create(CREATE, "4321"))
        self.assertEqual(self.last("error")["code"], "ssh-file-exists")
        self.assertEqual(self.runner.ran("ssh-keygen"), [])

    def test_create_failure_reports_the_code(self):
        self.registered()
        self.runner.answers[("ssh-keygen", "-t")] = helper.Result(255, "", "Key enrollment failed: PIN incorrect")
        self.run_op(self.session.ssh_create(CREATE, "0000"))
        self.assertEqual(self.last("error")["code"], "pin-invalid")

    def test_delete_takes_the_exact_credential_off_the_key_then_the_copy(self):
        name = "id_ed25519_sk_rk_github.com_work"
        ssh = self.ssh_key(name, "ssh:github.com", credential=b"MINE" * 16)
        (ssh / "config.d").mkdir()
        other = "id_ed25519_sk_rk_github.com_home"
        self.ssh_key(other, "ssh:github.com", credential=b"HOME" * 16)
        (ssh / "config.d" / "github.com.conf").write_text(helper.drop_in_text([name, other], ("git", "github.com", "")))
        self.registered()
        self.runner.answers[("fido2-token", "-L")] = helper.Result(0, DEVICES)
        listing = token_listing(b"HOME" * 16, b"MINE" * 16)

        async def token(args, stdin, env, cwd):
            if args[:3] == ["fido2-token", "-L", "-k"]:
                return helper.Result(0, listing)
            return None

        self.runner.hook = token
        self.run_op(self.session.ssh_delete(name, "4321"))
        listed = self.runner.ran("fido2-token", "-L", "-k")[0]
        self.assertEqual((listed[0][3:], listed[1]), (["ssh:github.com", "/dev/hidraw1"], "4321\n"))
        deleted = self.runner.ran("fido2-token", "-D")[0]
        self.assertEqual((deleted[0][3], deleted[1]), (base64.b64encode(b"MINE" * 16).decode(), "4321\n"))
        self.assertEqual(self.last("done"), {"type": "done", "op": "ssh.delete", "name": name})
        self.assertFalse((ssh / name).exists() or (ssh / (name + ".pub")).exists())
        self.assertEqual((ssh / "config.d" / "github.com.conf").read_text(),
                         helper.drop_in_text([other], ("git", "github.com", "")))

    def test_delete_refuses_a_copy_whose_key_is_not_on_the_security_key(self):
        # A copy kept after its key was replaced: same application and user ID,
        # another credential. Nothing may be deleted.
        name = "id_ed25519_sk_rk_github.com_work"
        ssh = self.ssh_key(name, "ssh:github.com", credential=b"OLD!" * 16)
        self.registered()

        async def token(args, stdin, env, cwd):
            if args[:3] == ["fido2-token", "-L", "-k"]:
                return helper.Result(0, token_listing(b"NEW!" * 16))
            return None

        self.runner.hook = token
        self.run_op(self.session.ssh_delete(name, "4321"))
        self.assertEqual(self.last("error")["code"], "ssh-not-on-key")
        self.assertEqual(self.runner.ran("fido2-token", "-D"), [])
        self.assertTrue((ssh / name).exists())

    def test_delete_checks_everything_before_touching_the_key(self):
        self.registered()
        ssh = self.ssh_key("id_ed25519_sk_rk_x", "ssh:x", cipher=b"aes256-ctr")
        self.run_op(self.session.ssh_delete("id_ed25519_sk_rk_x", "4321"))
        self.assertEqual(self.last("error")["code"], "ssh-encrypted")
        # The .pub of another key next to this handle.
        self.ssh_key("id_ed25519_sk_rk_y", "ssh:y")
        (ssh / "id_ed25519_sk_rk_y.pub").write_text(pub_text("ssh:y", point=b"\x02" * 32))
        self.run_op(self.session.ssh_delete("id_ed25519_sk_rk_y", "4321"))
        self.assertEqual(self.last("error")["code"], "ssh-damaged")
        # A drop-in edited by hand that lists the key.
        name = "id_ed25519_sk_rk_github.com"
        self.ssh_key(name, "ssh:github.com")
        (ssh / "config.d").mkdir()
        (ssh / "config.d" / "github.com.conf").write_text(
            helper.drop_in_text([name], ("git", "github.com", "")) + "    ForwardAgent no\n")
        self.run_op(self.session.ssh_delete(name, "4321"))
        self.assertEqual(self.last("error")["code"], "ssh-config-edited")
        self.assertEqual(self.runner.ran("fido2-token", "-L", "-k"), [])
        self.assertEqual(self.runner.ran("fido2-token", "-D"), [])

    def test_delete_with_a_wrong_pin(self):
        self.ssh_key("id_ed25519_sk_rk_x", "ssh:x")
        self.registered()

        async def token(args, stdin, env, cwd):
            if args[:3] == ["fido2-token", "-L", "-k"]:
                return helper.Result(1, "", "fido2-token: fido_credman_get_dev_rk: FIDO_ERR_PIN_INVALID")
            return None

        self.runner.hook = token
        self.run_op(self.session.ssh_delete("id_ed25519_sk_rk_x", "0000"))
        self.assertEqual(self.last("error")["code"], "pin-invalid")
        self.assertEqual(self.runner.ran("fido2-token", "-D"), [])

    def test_host_drop_in_and_include(self):
        name = "id_ed25519_sk_rk_github.com_work"
        ssh = self.ssh_key(name, "ssh:github.com")
        (ssh / "config").write_text("Host *\n    ServerAliveInterval 60\n")
        os.chmod(ssh / "config", 0o640)
        self.registered()
        self.assertEqual(self.session.ssh_entries()[0]["hostState"], "off")
        self.run_op(self.session.ssh_host(name, True))
        self.assertEqual(self.last("done")["enabled"], True)
        drop_in = ssh / "config.d" / "github.com.conf"
        self.assertEqual(drop_in.read_text().splitlines()[1:], [
            "Host github.com", "    User git", "    IdentityFile ~/.ssh/" + name,
            "    IdentitiesOnly yes", "    IdentityAgent none",
            # No connection reuse unless asked for, and none inherited either.
            "    ControlMaster no", "    ControlPath none", "    ControlPersist no"])
        self.assertEqual(stat.S_IMODE(drop_in.stat().st_mode), 0o600)
        self.assertEqual((ssh / "config").read_text(),
                         "Include config.d/*.conf\n\nHost *\n    ServerAliveInterval 60\n")
        self.assertEqual(stat.S_IMODE((ssh / "config").stat().st_mode), 0o640)
        self.assertEqual(self.session.ssh_entries()[0]["hostState"], "on")
        # Once is enough.
        self.run_op(self.session.ssh_host(name, True))
        self.assertEqual((ssh / "config").read_text().count("Include"), 1)
        # Removing the copy takes its line, and the drop-in with its last key.
        self.run_op(self.session.ssh_remove(name))
        self.assertFalse(drop_in.exists())

    def test_connection_reuse_per_host(self):
        name, other = "id_ed25519_sk_rk_github.com_work", "id_ed25519_sk_rk_github.com_home"
        ssh = self.ssh_key(name, "ssh:github.com")
        self.ssh_key(other, "ssh:github.com", credential=b"HOME" * 16)
        self.registered()
        self.run_op(self.session.ssh_host(name, True))
        self.assertEqual(self.session.ssh_entries()[1]["persistMinutes"], 0)
        drop_in = ssh / "config.d" / "github.com.conf"
        self.run_op(self.session.ssh_persist(name, 15))
        self.assertEqual(self.last("done"), {"type": "done", "op": "ssh.persist", "name": name,
                                             "host": "github.com", "minutes": 15})
        lines = drop_in.read_text().splitlines()
        self.assertEqual(lines[-3:], ["    ControlMaster auto", "    ControlPath ~/.ssh/noctalia-security-hw/control/%C",
                                      "    ControlPersist 15m"])
        control = ssh / "noctalia-security-hw" / "control"
        self.assertEqual(stat.S_IMODE(control.stat().st_mode), 0o700)
        # The host keeps its minutes when another key joins it, or one leaves.
        self.run_op(self.session.ssh_host(other, True))
        self.assertIn("    ControlPersist 15m", drop_in.read_text().splitlines())
        self.assertEqual({e["persistMinutes"] for e in self.session.ssh_entries()}, {15})
        self.run_op(self.session.ssh_host(other, False))
        self.assertIn("    ControlPersist 15m", drop_in.read_text().splitlines())
        # Back to authenticating each connection.
        self.run_op(self.session.ssh_persist(name, 0))
        self.assertEqual(drop_in.read_text().splitlines()[-3:],
                         ["    ControlMaster no", "    ControlPath none", "    ControlPersist no"])
        self.run_op(self.session.ssh_persist(name, 1440))
        self.assertIn("    ControlPersist 1440m", drop_in.read_text().splitlines())

    def test_setting_a_host_up_with_its_minutes(self):
        name = "id_ed25519_sk_rk_github.com"
        ssh = self.ssh_key(name, "ssh:github.com")
        self.registered()
        self.run_op(self.session.ssh_host(name, True, 20))
        self.assertIn("    ControlPersist 20m", (ssh / "config.d" / "github.com.conf").read_text().splitlines())
        self.run_op(self.session.ssh_host(name, True, 1441))
        self.assertEqual(self.last("error")["code"], "ssh-invalid")

    def test_connection_reuse_bounds_and_keys_without_a_host(self):
        name = "id_ed25519_sk_rk_github.com"
        self.ssh_key(name, "ssh:github.com")
        self.registered()
        for minutes in (-1, 1441, True, "15"):
            self.events.clear()
            self.run_op(self.session.ssh_persist(name, minutes))
            self.assertEqual(self.last("error")["code"], "ssh-invalid", minutes)
        # Only a key its host's drop-in already uses.
        self.run_op(self.session.ssh_persist(name, 15))
        self.assertEqual(self.last("error")["code"], "generic")
        self.assertFalse((self.home / ".ssh" / "config.d").exists())

    def test_a_drop_in_without_control_lines_stays_ours(self):
        # No Control lines: still the helper's, reported as no reuse,
        # and rewritten with them on the next change.
        name = "id_ed25519_sk_rk_github.com"
        ssh = self.ssh_key(name, "ssh:github.com")
        (ssh / "config").write_text(helper.SSH_INCLUDE + "\n")
        (ssh / "config.d").mkdir()
        legacy = helper.drop_in_text([name], ("git", "github.com", ""), None)
        self.assertNotIn("Control", legacy)
        (ssh / "config.d" / "github.com.conf").write_text(legacy)
        self.registered()
        self.assertEqual(self.session.ssh_entries()[0]["hostState"], "on")
        self.assertEqual(self.session.ssh_entries()[0]["persistMinutes"], 0)
        self.run_op(self.session.ssh_persist(name, 30))
        self.assertIn("    ControlPersist 30m", (ssh / "config.d" / "github.com.conf").read_text().splitlines())
        # A hand-edited duration is no longer the helper's.
        text = (ssh / "config.d" / "github.com.conf").read_text().replace("30m", "2h")
        (ssh / "config.d" / "github.com.conf").write_text(text)
        self.assertEqual(self.session.ssh_entries()[0]["hostState"], "edited")

    def test_host_drop_ins_never_take_over_other_files(self):
        name = "id_ed25519_sk_rk_github.com"
        ssh = self.ssh_key(name, "ssh:github.com")
        (ssh / "config.d").mkdir()
        drop_in = ssh / "config.d" / "github.com.conf"
        drop_in.write_text("Host github.com\n    User git\n")
        self.registered()
        self.assertEqual(self.session.ssh_entries()[0]["hostState"], "foreign")
        self.run_op(self.session.ssh_host(name, True))
        self.assertEqual(self.last("error")["code"], "ssh-config-foreign")
        self.assertEqual(drop_in.read_text(), "Host github.com\n    User git\n")
        # Removing the copy leaves that file alone too.
        self.run_op(self.session.ssh_remove(name))
        self.assertEqual(self.last("done")["op"], "ssh.remove")
        self.assertEqual(drop_in.read_text(), "Host github.com\n    User git\n")

    def test_host_refuses_a_symlinked_config(self):
        name = "id_ed25519_sk_rk_github.com"
        ssh = self.ssh_key(name, "ssh:github.com")
        (ssh / "real-config").write_text("")
        (ssh / "config").symlink_to("real-config")
        self.registered()
        self.run_op(self.session.ssh_host(name, True))
        self.assertEqual(self.last("error")["code"], "ssh-config-link")
        self.assertFalse((ssh / "config.d" / "github.com.conf").exists())

    def test_gpg_import_says_when_it_updated_a_key(self):
        self.registered()
        self.run_op(self.session.gpg_import())
        self.assertEqual(self.last("done"), {"type": "done", "op": "gpg.import", "updated": True})
        self.runner.answers[("gpg", "--list-keys")] = helper.Result(2, "")
        self.run_op(self.session.gpg_import())
        self.assertEqual(self.last("done")["updated"], False)


    # -- what the Noctalia port adds -------------------------------------

    def test_ssh_entries_describe_the_copy(self):
        name = "id_ed25519_sk_rk_github.com_work"
        self.ssh_key(name, "ssh:github.com")
        self.registered()
        entry = self.session.ssh_entries()[0]
        self.assertEqual((entry["type"], entry["user"], entry["encrypted"]), ("ed25519-sk", "work", False))
        public = helper.parse_public(pub_text("ssh:github.com"))
        self.assertEqual(entry["fingerprint"], helper.fingerprint(public["blob"]))
        self.assertTrue(entry["fingerprint"].startswith("SHA256:") and not entry["fingerprint"].endswith("="))
        self.assertEqual(entry["publicKey"], pub_text("ssh:github.com").strip())

    def test_name_user(self):
        self.assertEqual(helper.name_user("id_ed25519_sk_rk_github.com_work", "ed25519-sk", "ssh:github.com"), "work")
        self.assertEqual(helper.name_user("id_ed25519_sk_rk_github.com", "ed25519-sk", "ssh:github.com"), "")
        self.assertEqual(helper.name_user("id_ecdsa_sk_rk_abc", "ecdsa-sk", "ssh:"), "abc")
        self.assertEqual(helper.name_user("id_ed25519_sk_rk_other_x", "ed25519-sk", "ssh:github.com"), "")

    def test_import_installs_only_complete_pairs(self):
        self.registered()

        async def keygen(args, stdin, env, cwd):
            if args[0] != "ssh-keygen":
                return None
            pathlib.Path(cwd, "id_ed25519_sk_rk_half").write_text("key")
            pathlib.Path(cwd, "id_ed25519_sk_rk_full").write_text("key")
            pathlib.Path(cwd, "id_ed25519_sk_rk_full.pub").write_text("pub")
            return helper.Result(0)

        self.runner.hook = keygen
        self.run_op(self.session.ssh_import(""))
        self.assertEqual(self.last("done")["imported"], ["id_ed25519_sk_rk_full"])
        self.assertEqual(sorted(os.listdir(self.home / ".ssh")), ["id_ed25519_sk_rk_full", "id_ed25519_sk_rk_full.pub"])

    def test_a_home_manager_config_that_includes_config_d_is_used_as_it_is(self):
        # home-manager links ~/.ssh/config into the Nix store, with its includes on top.
        name = "id_ed25519_sk_rk_github.com"
        ssh = self.ssh_key(name, "ssh:github.com")
        store = pathlib.Path(self.tmp.name) / "store-config"
        store.write_text("Include ~/.ssh/config.d/*.conf\n\nHost *\n  ServerAliveInterval 60\n")
        os.chmod(store, 0o444)
        (ssh / "config").symlink_to(store)
        self.registered()
        self.assertEqual(self.session.ssh_include_state(), "ok")
        self.run_op(self.session.ssh_host(name, True))
        self.assertEqual(self.last("done")["enabled"], True)
        self.assertTrue((ssh / "config").is_symlink())
        self.assertEqual(self.session.ssh_entries()[0]["hostState"], "on")
        store.chmod(0o644)
        store.write_text("Host *\n")
        self.assertEqual(self.session.ssh_include_state(), "link")

    def test_execute_ends_every_operation(self):
        async def scenario():
            started = asyncio.Event()

            async def slow(args, stdin, env, cwd):
                if args[0] == "pamu2fcfg":
                    started.set()
                    await asyncio.sleep(10)
                return None

            self.runner.hook = slow
            running = asyncio.ensure_future(self.session.execute("fido.register", self.session.fido_register("1")))
            await started.wait()
            self.session.cancel()
            await running

        self.session.devices = [{"path": "/dev/hidraw1", "clientPin": True}]
        asyncio.run(scenario())
        self.assertTrue(self.runner.cancelled)
        self.assertEqual([e["type"] for e in self.events[-2:]], ["cancelled", "end"])

        async def broken():
            raise RuntimeError("boom")

        asyncio.run(self.session.execute("gpg.trust", broken()))
        self.assertEqual(self.events[-2]["code"], "generic")
        self.assertEqual(self.events[-1], {"type": "end", "op": "gpg.trust"})

    def test_pin_files(self):
        pins = pathlib.Path(self.paths.pins)
        pins.mkdir(mode=0o700)
        path = pins / "pin-1"
        path.write_text("2468\n")
        args = ["ssh", "import", "--pin-file", str(path)]
        self.assertEqual(cli.pop_pin(args, self.paths), "2468")
        self.assertEqual(args, ["ssh", "import"])
        self.assertFalse(path.exists())
        outside = pathlib.Path(self.tmp.name) / "pin"
        outside.write_text("1")
        with self.assertRaises(helper.PinFileError):
            cli.pop_pin(["--pin-file", str(outside)], self.paths)
        (pins / "link").symlink_to(outside)
        with self.assertRaises(helper.PinFileError):
            cli.pop_pin(["--pin-file", str(pins / "link")], self.paths)
        self.assertEqual(outside.read_text(), "1")

    def test_command_lines(self):
        op, coroutine = cli.operation(self.session, "ssh", "host", ["k", "on", "15"], "")
        coroutine.close()
        self.assertEqual(op, "ssh.host")
        op, coroutine = cli.operation(self.session, "ssh", "create", ['{"algorithm":"ed25519-sk"}'], "1")
        coroutine.close()
        self.assertEqual(op, "ssh.create")
        for area, action, args in (("ssh", "create", ["[1]"]), ("ssh", "host", ["k", "maybe"]),
                                   ("fido", "remove", []), ("nope", "", [])):
            with self.assertRaises(cli.Usage):
                cli.operation(self.session, area, action, args, "")


if __name__ == "__main__":
    unittest.main()
