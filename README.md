# Security Hardware for Noctalia

A [Noctalia](https://github.com/noctalia-dev/noctalia) plugin: one panel for the security
hardware on your desk, with a tab for each thing it can do. A tab shows only when the
hardware plugged in can do that thing.

| Tab | Shows when | Does |
| --- | --- | --- |
| **Fingerprint** | fprintd knows a reader | Enrolls, tests and deletes fingers, and picks the reader when there is more than one |
| **Sign in** | A FIDO2 key is plugged in, or keys are registered | Registers the key for `pam_u2f` (sudo, polkit, the lock screen), removes registrations, tests the key |
| **OpenPGP** | An OpenPGP card is present | Imports, updates or links the card's public key, trusts it, removes it from the keyring |
| **SSH** | The key keeps resident credentials, or `~/.ssh` holds copies | Imports resident SSH keys into `~/.ssh`, creates new ones, removes a copy, deletes a key from the security key, sets ssh up for git hosts |

The panel notices a key being plugged in or pulled out while it is open.

The panel opens from a control-center shortcut, or with:

```sh
noctalia msg panel-toggle lbssousa/security-hardware:panel
```

It was modelled on [security-key-omarchy](https://github.com/lbssousa/security-key-omarchy) and on
[omarchy-yubikey](https://github.com/marselnenaj/omarchy-yubikey). Noctalia's
[SCOPE.md](https://github.com/noctalia-dev/noctalia/blob/main/SCOPE.md) puts hardware-specific
controls in plugins, so this is a plugin rather than a Settings page.

## Keyboard

| Key | Does |
| --- | --- |
| Ctrl+Tab / Ctrl+Shift+Tab | Next / previous tab |
| F5 | Refresh |
| Alt+R | Register the FIDO2 key |
| Alt+I | Import, link or update the OpenPGP key |
| Alt+S | Import the resident SSH keys |
| Alt+N | Add a fingerprint, or open the form for a new SSH key, depending on the tab |
| Alt+T | Test the fingerprint or the key, or trust the OpenPGP key, depending on the tab |
| Enter | In the PIN dialog or a form field, run the action |
| Escape | Close the panel; anything still running stops |

## PINs

When the key has a PIN, an action that needs it asks in a dialog in the panel, then waits for
a touch. A wrong PIN keeps the dialog open, with the number of tries left.

The PIN never goes on a command line or into the environment. The panel writes it to a new
`0600` file under `$XDG_RUNTIME_DIR/noctalia-security-hw/`, and the helper reads and removes
that file at once. For `pamu2fcfg` and `fido2-token`, the helper passes the PIN on stdin. For
`ssh-keygen`, the helper acts as `SSH_ASKPASS` itself and hands over the PIN through a socket in
a private folder.

## Resident SSH keys

These rules come from omarchy-yubikey. They keep the files in `~/.ssh` safe:

- **Import** runs `ssh-keygen -K` in a private temporary folder. Only complete pairs are copied
  into `~/.ssh`, with mode `0600` for the key and `0644` for the `.pub`. The import never
  overwrites a file, nor either half of an existing pair. A pair whose copy fails halfway is
  removed again.
- **New key** makes the key on the security key with `ssh-keygen -O resident`. You choose:
  - the type: `ed25519-sk`, or `ecdsa-sk` for YubiKey firmware older than 5.2.3;
  - the application, which goes after `ssh:`, such as `github.com`;
  - the user ID, which defaults to a random one;
  - whether every use needs the PIN and a touch;
  - the comment.

  The options are checked before the key is touched, so the copy gets the name `ssh-keygen -K`
  would give it. If the security key already has a key with the same application and user ID,
  the panel asks before replacing it. Replacing deletes the old key for good.
- **Remove copy** deletes only the files in `~/.ssh`. The key stays on the security key and can
  be imported again.
- **Delete from security key** takes two presses and the PIN, and cannot be undone. It deletes
  only the exact credential of that copy, found by the key handle in its file (`fido2-token -L -k`,
  then `-D`). A copy of a key that was replaced since, or made on another security key, deletes
  nothing. Copies with a passphrase are refused, because their key handle can't be read.
- **Use for &lt;host&gt;** appears for a key whose application names a git host: a well-known
  forge, or a host with `git` in its name. It writes `~/.ssh/config.d/<host>.conf`, so ssh uses the
  keys for that host without the agent:

  ```
  Host github.com
      User git
      IdentityFile ~/.ssh/id_ed25519_sk_rk_github.com_…
      IdentitiesOnly yes
      IdentityAgent none
      ControlMaster no
      ControlPath none
      ControlPersist no
  ```

  **Reuse connections** sets how many minutes ssh keeps an authenticated connection open for
  later ones to reuse. It goes from 0, the default, to 1440. During that time, new connections
  need no PIN or touch.

  The panel only changes files it wrote, which carry a marker on their first line. A file written
  or changed by hand is left alone. If `~/.ssh/config` doesn't include `config.d` yet, the panel
  adds `Include config.d/*.conf` at its top. It never writes to a symbolic link. Under
  home-manager, add the include yourself:

  ```nix
  programs.ssh.includes = [ "~/.ssh/config.d/*.conf" ];
  ```

## Sign in (pam_u2f)

The panel registers a key only where sudo and polkit will read it. It looks at the `pam_u2f.so`
lines of `/etc/pam.d/sudo` and `/etc/pam.d/polkit-1`. When they use pam_u2f's per-user default,
`~/.config/Yubico/u2f_keys`, the panel saves the key there.

The panel refuses to register in these cases, and says why:

- the lines name another `authfile=`;
- the two services read different files;
- neither service asks for a key.

When the lines say `pinverification=1`, a key without a PIN is turned away, since it could never
sign in. The panel also refuses a key that is already registered, which it checks without
asking for a touch.

Test runs `pamtester` against the PAM service `noctalia-lock-u2f`. Set
`NOCTALIA_SECURITY_HW_U2F_SERVICE` to use another service.

## The helper

Luau plugins can't use D-Bus or write to a process's stdin. The plugin therefore runs
`noctalia-security-hw` (`helper/`), a Python program that uses only the standard library, plus
PyGObject for fprintd. It runs one operation per process and prints one JSON event per line;
the last event is always `{"type": "end"}`. Its commands and events are listed in
`helper/noctalia_security_hw/cli.py`.

Requirements:

- Python 3, and PyGObject (Gio) for fingerprints;
- `fprintd`;
- `fido2-token` and `fido2-assert` (libfido2);
- `pamu2fcfg` (pam_u2f);
- `pamtester`;
- `gpg`;
- `ssh-keygen` (OpenSSH 8.3 or newer).

## Installation

```sh
noctalia msg plugins source add security-hardware git https://github.com/lbssousa/noctalia-security-hardware
noctalia msg plugins enable lbssousa/security-hardware
```

Then install the helper, from a checkout:

```sh
install -Dm755 helper/noctalia-security-hw ~/.local/lib/noctalia-security-hw/noctalia-security-hw
cp -r helper/noctalia_security_hw ~/.local/lib/noctalia-security-hw/
ln -s ~/.local/lib/noctalia-security-hw/noctalia-security-hw ~/.local/bin/noctalia-security-hw
```

The plugin needs Noctalia with plugin API 42 or newer. Its `helper` setting holds the helper's
command, and defaults to `noctalia-security-hw` on `PATH`.

With Nix, `nix build github:lbssousa/noctalia-security-hardware` builds a wrapped helper with
every dependency, and `overlays.default` adds `pkgs.noctalia-security-hw`.

## Development

```sh
nix build      # runs both test suites in the check phase
python3 -m unittest discover -s helper/tests
python3 tests/bundle.py tests/panel_test.luau en > /tmp/panel.luau && luau /tmp/panel.luau
```

`tests/panel_test.luau` runs the panel against a mock of the Noctalia plugin API. It drives every
tab through its flows by feeding the panel helper events. It also checks each `ui.*` prop against
the ones the shell knows, and makes sure every translation key exists, in English and in
Brazilian Portuguese.

## License

MIT
