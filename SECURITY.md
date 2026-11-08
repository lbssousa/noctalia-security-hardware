# Security policy

This plugin handles security hardware: it registers keys for `pam_u2f`, deletes resident SSH
keys from a security key, writes `~/.ssh` and passes PINs to `pamu2fcfg`, `fido2-token` and
`ssh-keygen`. Fixes go to `main`. Report problems against the latest commit.

## Reporting a vulnerability

Use **Security → Report a vulnerability** on this repository, which opens a private advisory.
Please don't open a public issue for a vulnerability.

A useful report includes:

- the commit;
- your Noctalia version;
- what you expected and what happened;
- a minimal reproduction with synthetic data.

Never include PINs, `u2f_keys` lines, SSH key handles, private keys or unredacted logs. This is
a personal project: there is no guaranteed response time.

## What is in scope

- A PIN reaching a command line, the environment, a log, or a file other than the plugin's
  `0600` PIN file. The PIN file lives under `$XDG_RUNTIME_DIR/noctalia-security-hw/`, and the
  helper removes it as soon as it has read it.
- The helper writing outside the files it owns:
  - `~/.config/Yubico/u2f_keys`, the user's own line only;
  - resident key pairs in `~/.ssh`, never over an existing file;
  - its marked `~/.ssh/config.d/<host>.conf` files;
  - the `Include` line at the top of a regular `~/.ssh/config`.
- Following a symbolic link it should refuse.
- Deleting a credential from a security key other than the exact one behind the copy chosen.
- Path tricks through plugin input: SSH key names, the PIN file path, the options of a new key.

The model this relies on: the plugin and its helper run as you, with no privileges. Anyone who
can already run code as you can read what you can. Hardware behavior (touch, PIN retries) is the
security key's own.

## Automated checks

Every push and pull request runs:

- **Checks:** `nix flake check`, which builds the helper and runs its unit tests and the panel's
  tests against a mock of the plugin API; Nix formatting; and a gitleaks scan of the tree and the
  whole history, with a pinned version and SHA-256.
- **CodeQL:** Python and the workflows, with the `security-extended` queries.
- **zizmor:** a static audit of the GitHub Actions workflows.
- **Dependency review** on pull requests.

The OpenSSF Scorecard runs weekly and on pushes to `main`. Dependabot updates the actions
weekly, after a seven-day cooldown. Every action is pinned to a commit SHA.

These checks catch known classes of problems. They don't replace review or testing on real
hardware.
