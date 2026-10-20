# Installing opencraysec

opencraysec is one self-contained program, `opencraysec`. It needs no daemon, no account and no
API key.

## One-line install

```sh
curl -fsSL https://raw.githubusercontent.com/amgio38/opencraysec/main/scripts/install.sh | sh
```

| Platform | What happens |
| --- | --- |
| Linux x86-64, aarch64 | Downloads a prebuilt static binary from the newest GitHub Release. No Rust needed. |
| macOS, Apple Silicon (arm64) and Intel (x86-64) | Downloads a prebuilt native binary from the newest GitHub Release. No Rust or Xcode needed. A shell running under Rosetta on an Apple Silicon Mac still gets the arm64 binary. |
| Other Linux CPUs | Builds from source with cargo (Rust 1.95 or newer and a C compiler). |

The macOS binaries are built for macOS 11 or newer and are not notarized. The installer downloads
them with `curl`, which does not mark them as quarantined, so they run as they are. A binary you
download from a browser instead carries the quarantine flag, and Gatekeeper asks you to allow it
(or run `xattr -d com.apple.quarantine opencraysec`).
| Windows | Run the installer inside **WSL2** (`wsl --install -d Ubuntu`, then open Ubuntu). The installer refuses to run in native Windows shells. |

CI builds and tests the workspace on Linux and macOS, and on native Windows as an experiment (a
failure there is reported but does not block a merge). Until Windows is green and verified, WSL2 is
the supported way to run opencraysec on Windows.

Options go after `sh -s --`:

```sh
curl -fsSL https://raw.githubusercontent.com/amgio38/opencraysec/main/scripts/install.sh | sh -s -- --prefix /opt/tools --version v0.20261020.1
```

| Option | Effect |
| --- | --- |
| `--prefix DIR` | Install under `DIR/bin` and the licence files under `DIR/share/doc/opencraysec`. Default: `$PREFIX`, else `~/.local`. |
| `--destdir DIR` | Staging prefix prepended to `--prefix`, for packagers. |
| `--version TAG` | Install that release instead of the newest. |
| `--from-source` | Skip release assets and build with cargo. |
| `--insecure` | Install a release asset that has no published checksum. Off by default. |

Environment: `PREFIX`, `DESTDIR`, `OPENCRAYSEC_VERSION`, `OPENCRAYSEC_REPO` (`owner/name`),
`OPENCRAYSEC_INSECURE`.

### What the installer guarantees

- A release asset is installed only after its published SHA-256 matches. No checksum, an empty
  checksum, or a machine without `sha256sum`/`shasum` stops the install; `--insecure` is the only way
  past it.
- Downloads are pinned to HTTPS and TLS 1.2 or newer, with timeouts.
- The archive may contain the program and the licence directory and nothing else; names with `..`
  are refused. The licence files are checked **before** anything is placed in `bin/`, so a refusal
  never leaves a binary without its licences.
- The program is staged in a private `mktemp -d` directory inside `bin/`, run once with
  `--version`, and only then renamed into place. A failed upgrade leaves the previous version alone.
- It never uses `sudo`, never edits a client configuration, and refuses prefixes such as
  `/usr/bin` (use `--prefix /usr/local`) or one that ends in `/bin`.
- The whole script runs from its last line, so a truncated download does nothing.

These properties are tested with the network stubbed: `scripts/install-sh.test.sh`.

## Build from a checkout

```sh
git clone https://github.com/amgio38/opencraysec
cd opencraysec
make install                      # ~/.local/bin/opencraysec
make install PREFIX=/usr/local    # system-wide (needs the right privileges)
make uninstall
```

`make install` builds in release mode, stages and checks the binary the same way the installer
does, and installs the licence files from `scripts/doc-files.sh`. Or build without installing:

```sh
cargo build --release -p opencraysec-cli    # target/release/opencraysec
```

The crates are `publish = false`: opencraysec is released as a binary, not as a library, so
`cargo install opencraysec` from crates.io does not exist. `cargo install --locked --path
crates/cli` from a checkout works.

A static Linux binary of your own:

```sh
rustup target add x86_64-unknown-linux-musl
sudo apt install musl-tools        # the TLS stack compiles a little C
make release-static                # dist/opencraysec
```

## Uninstall

```sh
sh scripts/uninstall.sh                  # or: make uninstall
sh scripts/uninstall.sh --prefix /usr/local
```

This removes the binary and its licence directory. It leaves your data alone (the advisory database
and the activity log); delete the data directory yourself if you want it gone. See
[CONFIGURATION.md](CONFIGURATION.md) for where it is.

## First run

```sh
opencraysec --version
opencraysec update --for .      # download advisories for the ecosystems found under this directory
opencraysec scan .
```

`update --for .` downloads only what the project needs. npm advisories are large (several hundred
MB), so `--all` is a deliberate choice. Without local data, `scan` asks the OSV API about the exact
package names and versions it found and says so in the report; `--offline` forbids that.

To let an AI assistant use it, see [CLIENTS.md](CLIENTS.md).

## Verifying a download by hand

Every release asset has a `.sha256` next to it:

```sh
curl -fsSLO https://github.com/amgio38/opencraysec/releases/latest/download/opencraysec-x86_64-unknown-linux-musl.tar.gz
curl -fsSLO https://github.com/amgio38/opencraysec/releases/latest/download/opencraysec-x86_64-unknown-linux-musl.tar.gz.sha256
sha256sum -c opencraysec-x86_64-unknown-linux-musl.tar.gz.sha256
tar -tzf opencraysec-x86_64-unknown-linux-musl.tar.gz
```
