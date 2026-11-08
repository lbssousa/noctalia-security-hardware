# Security Hardware for Noctalia

A [Noctalia](https://github.com/noctalia-dev/noctalia) plugin with a panel to manage:

- **Fingerprints** through fprintd: enroll, verify and delete fingers. When there is
  more than one reader, you choose which one to use.
- **FIDO2/U2F security keys** for `pam_u2f`: register a key in
  `~/.config/Yubico/u2f_keys`, remove a key, and test a key against a PAM service.
- **The OpenPGP card key** (for example a YubiKey): import the public key from the card
  URL, the keyservers or a file, then mark it as ultimately trusted.

Noctalia's [SCOPE.md](https://github.com/noctalia-dev/noctalia/blob/main/SCOPE.md) puts
hardware-specific controls in plugins, so this is a plugin rather than a Settings page.
The panel opens from a control-center shortcut, or with:

```sh
noctalia msg panel-toggle lbssousa/security-hardware:panel
```

## The helper

Luau plugins cannot use D-Bus or write to a process's stdin. The plugin therefore runs
`noctalia-security-hw`, a Python helper. The helper runs one operation per process and
prints one JSON object per line. The `fp`, `key` and `gpg` subcommands are listed at
the top of `helper/noctalia-security-hw.py`.

The helper needs:

- runtime: Python 3 with PyGObject (Gio), and `fprintd` running;
- on `PATH`: `pamu2fcfg` (pam_u2f), `fido2-token` (libfido2), `pamtester` and `gpg`.

`key test` runs `pamtester` against the PAM service `noctalia-lock-u2f`. To test
against another service, set `NOCTALIA_SECURITY_HW_U2F_SERVICE`. The Test button is
disabled while that service is missing from `/etc/pam.d`.

## Installation

```sh
noctalia msg plugins source add security-hardware git https://github.com/lbssousa/noctalia-security-hardware
noctalia msg plugins enable lbssousa/security-hardware
install -Dm755 helper/noctalia-security-hw.py ~/.local/bin/noctalia-security-hw
```

The plugin needs Noctalia with plugin API 42 or newer.

The plugin setting `helper` holds the helper's command, and defaults to
`noctalia-security-hw` on `PATH`. With Nix, `nix build github:lbssousa/noctalia-security-hardware`
gives a wrapped helper with every dependency. `overlays.default` adds
`pkgs.noctalia-security-hw`.

## License

MIT
