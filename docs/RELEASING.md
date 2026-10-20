# Releasing

One command cuts a release, and it enforces the order:

```sh
bash scripts/release.sh            # plan + preflight only, pushes nothing
bash scripts/release.sh --publish  # preflight, push main, wait for CI green, tag, push tag, wait for the release workflow green
```

[`scripts/release.sh`](../scripts/release.sh) refuses to run off `main`, refuses a tag that already
exists locally or on `origin`, refuses a version with no `CHANGELOG.md` section, and creates the tag
**only after CI on the pushed commit has finished green**. A published release therefore always points
at a green commit. The release workflow repeats the tag check on its side: a tag that differs from the
crate version, or a version with no changelog section, is refused before anything is built.

Only the maintainer pushes. `--publish` needs `git` and an authenticated `gh` that may push to
`origin`.

## Before it: the commit that opens a release

1. Set the version in the root `Cargo.toml`: the `[workspace.package]` version **and** the
   `opencraysec-*` path-dependency pins in `[workspace.dependencies]`. Then refresh the lockfile with
   `cargo update --workspace --offline`.
2. Cut the `CHANGELOG.md` section, headed `## [<version>] - <date>`, in the same commit (move the
   *Unreleased* entries under it).
3. Regenerate the licence inventory if the dependency set changed:
   `python3 scripts/gen-third-party-licenses.py`.
4. Commit, then run `bash scripts/release.sh`.

Versions are `0.YYYYMMDD.N`: the date of the release and a counter for several on one day.

## What a release contains

The release workflow ([`.github/workflows/release.yml`](../.github/workflows/release.yml)) builds the
program on a runner of each target's own architecture: a static musl binary for Linux x86-64 and
aarch64, and a native binary for macOS on Apple Silicon (`macos-15`) and on Intel (`macos-15-intel`).
It checks the Linux binaries are statically linked, and the macOS ones load only system libraries
(`otool -L`) and, on arm64, carry a valid signature. It runs `--version` once, and packs `opencraysec`
plus the licence files listed in [`scripts/doc-files.sh`](../scripts/doc-files.sh) under
`share/doc/opencraysec`. Each archive gets a `.sha256`. Each archive is packed with `COPYFILE_DISABLE=1` (macOS adds hidden `._name` members otherwise)
and checked by [`scripts/check-release-archive.sh`](../scripts/check-release-archive.sh) against exactly what
`install.sh` accepts, so one stray member fails the build instead of making the release uninstallable. A separate job publishes the GitHub Release
**only if all four targets built**, so a release never ships with one platform missing.

GitHub has said `macos-15-intel` is its last Intel macOS image (supported until 2027). When it is
retired, build `x86_64-apple-darwin` on the arm64 runner with `--target`, or stop publishing it.

`scripts/install.sh` installs exactly this archive shape and refuses anything else; see
[INSTALL.md](INSTALL.md).

To rehearse the build without publishing, run the *release* workflow by hand from the Actions tab: it
builds and checks all four archives and keeps them as workflow artifacts, but creates no release.

## Rules that never bend

- **Nothing is pushed before [`scripts/preflight.sh`](../scripts/preflight.sh) passes** on the exact
  tree being pushed (`make preflight`). It runs what CI runs, in the same order: format, clippy with
  default and all features, the **whole** workspace test suite, the layering, licence, installer,
  `cargo deny`, docs and parity checks, and the 90% coverage gate. "I ran the relevant checks" is how a
  red CI gets published. `PREFLIGHT_QUICK=1` skips only the slow coverage step locally; CI still runs it.
- `scripts/check-preflight-parity.sh` fails, in preflight and in CI, when `ci.yml` runs a command that
  `preflight.sh` does not, so the two lists cannot drift apart unnoticed.
- A tag is never moved, reused or deleted. If anything fails after the tag is public, fix forward with
  a new version.
- The audit workflow re-checks advisories for our own dependencies weekly and on every tag.
- Open-source commits are in English and describe what changed; they carry no internal ticket numbers.

## Cutting the very first public release

1. Create the public repository `amgio38/opencraysec`, enable *private vulnerability reporting*
   (Settings, Security) so [SECURITY.md](../SECURITY.md) has a working channel, and enable Dependabot
   alerts.
2. Turn on branch protection for `main` and require these checks, named exactly as the workflow jobs are: `fmt, clippy, test, checks`, `line coverage (90% per crate and per file)` and `build and test (macos-latest)`. The Windows job is experimental and
   must not be required until it is green.
3. Rehearse the release workflow once by hand (above) and read the archive listing it prints.
4. Run `bash scripts/release.sh --publish`.
