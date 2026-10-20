#!/bin/sh
# End-to-end tests for scripts/install.sh and scripts/uninstall.sh, with the network replaced.
#
# `curl` and `uname` are stubbed on PATH, so the real script runs -- argument parsing, the tar
# member allowlist, checksum verification, the staging -- against a tarball built here. That is
# the only way to test the things that matter, which are decisions the script makes about
# *failure*: an unverified, malformed or broken release asset must not end up in $BINDIR.
#
# Usage: install-sh.test.sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$here/.." && pwd)
installer="$here/install.sh"
uninstaller="$here/uninstall.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

fail=0
ok() { echo "ok: $1"; }
bad() {
	echo "FAIL: $1" >&2
	[ $# -lt 2 ] || echo "  $2" >&2
	fail=1
}

if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
	echo "skip: no SHA-256 tool on this machine, so the installer cannot be exercised"
	exit 0
fi
sha_of() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi
}

# --- the licence files a real release ships, from the real list ------------
doc_subdir=$(
	. "$here/doc-files.sh"
	printf '%s' "$OPENCRAYSEC_DOC_SUBDIR"
)
doc_files=$(
	. "$here/doc-files.sh"
	printf '%s\n' $OPENCRAYSEC_DOC_FILES
)

asset_name=opencraysec-x86_64-unknown-linux-musl.tar.gz

# Builds $work/serve-<name>/$asset_name (+ .sha256) from a staging directory.
# $1 = case name; the program is whatever $2 names (default: one that prints a version).
build_asset() {
	name=$1
	stage="$work/stage-$name"
	rm -rf "$stage"
	mkdir -p "$stage"
	cat > "$stage/opencraysec" <<'EOF'
#!/bin/sh
echo "opencraysec 0.1.0"
EOF
	chmod 0755 "$stage/opencraysec"
	for f in $doc_files; do
		install -D -m 0644 "$repo_root/$f" "$stage/$doc_subdir/$f"
	done
	mkdir -p "$work/serve-$name"
}
pack() {
	name=$1
	shift
	(cd "$work/stage-$name" && tar -czf "$work/serve-$name/$asset_name" "$@")
	(cd "$work/serve-$name" && sha_of "$asset_name" > "$asset_name.sha256")
}

# --- stubs -----------------------------------------------------------------
stub_dir="$work/bin"
mkdir -p "$stub_dir"
cat > "$stub_dir/curl" <<'EOF'
#!/bin/sh
# Stands in for `curl -fsSL --proto '=https' --tlsv1.2 ... <url> -o <out>`. Every call is
# recorded so a case can assert on the flags themselves.
[ -z "${STUB_LOG:-}" ] || printf '%s\n' "$*" >>"$STUB_LOG"
out=
url=
prev=
for arg in "$@"; do
	case "$prev" in -o) out=$arg ;; esac
	case "$arg" in *.tar.gz | *.tar.gz.sha256) url=$arg ;; esac
	prev=$arg
done
[ -n "$url" ] || exit 2
# The script must ask for the asset this machine needs; anything else is a 404.
case "${url##*/}" in "$SERVE_ASSET" | "$SERVE_ASSET.sha256") ;; *) exit 22 ;; esac
case "$url" in
*.sha256)
	[ -n "${STUB_NO_CHECKSUM:-}" ] && exit 22
	if [ -n "${STUB_EMPTY_CHECKSUM:-}" ]; then : > "$out"; else cp "$SERVE_DIR/$SERVE_ASSET.sha256" "$out"; fi ;;
*) cp "$SERVE_DIR/$SERVE_ASSET" "$out" ;;
esac
EOF
chmod 0755 "$stub_dir/curl"
# The tests describe a Linux x86_64 machine whatever they run on, unless a case says otherwise.
cat > "$stub_dir/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in -m) echo "${STUB_ARCH:-x86_64}" ;; *) echo "${STUB_OS:-Linux}" ;; esac
EOF
chmod 0755 "$stub_dir/uname"
# Only asked on macOS: 1 on Apple Silicon hardware, even from a shell running under Rosetta.
cat > "$stub_dir/sysctl" <<'EOF'
#!/bin/sh
[ "${STUB_APPLE_SILICON:-0}" = 1 ] && echo 1 || echo 0
EOF
chmod 0755 "$stub_dir/sysctl"

# A failed download falls back to a source build, which must never really run in a test: it would
# compile this checkout for minutes. With this stub the fallback fails at once and installs nothing.
cat > "$stub_dir/cargo" <<'EOF'
#!/bin/sh
echo "cargo stub: no source builds in tests" >&2
exit 1
EOF
chmod 0755 "$stub_dir/cargo"

mkdir -p "$work/home"

# run_install <serve case> <prefix> [installer args]  -> prints the exit code
run_install() {
	case_name=$1 prefix=$2
	shift 2
	env -i \
		PATH="$stub_dir:$PATH" \
		HOME="$work/home" \
		SERVE_DIR="$work/serve-$case_name" \
		SERVE_ASSET="${STUB_SERVE_ASSET:-$asset_name}" \
		${STUB_OS:+STUB_OS="$STUB_OS"} \
		${STUB_ARCH:+STUB_ARCH="$STUB_ARCH"} \
		${STUB_APPLE_SILICON:+STUB_APPLE_SILICON="$STUB_APPLE_SILICON"} \
		STUB_LOG="${STUB_LOG:-}" \
		${STUB_NO_CHECKSUM:+STUB_NO_CHECKSUM=1} \
		${STUB_EMPTY_CHECKSUM:+STUB_EMPTY_CHECKSUM=1} \
		${OPENCRAYSEC_REPO:+OPENCRAYSEC_REPO="$OPENCRAYSEC_REPO"} \
		sh "$installer" --prefix "$prefix" "$@" >"$work/out" 2>"$work/err" && echo 0 || echo $?
}

run_uninstall() {
	prefix=$1
	shift
	env -i PATH="$stub_dir:$PATH" HOME="$work/home" \
		sh "$uninstaller" --prefix "$prefix" "$@" >"$work/uout" 2>"$work/uerr" && echo 0 || echo $?
}

nothing_installed() {
	[ ! -e "$1/bin/opencraysec" ] && [ ! -e "$1/$doc_subdir" ]
}
no_staging_left() {
	[ -z "$(find "$1" -name '.opencraysec.install.*' 2>/dev/null)" ]
}

# --- a verified release installs --------------------------------------------
build_asset good
pack good opencraysec "$doc_subdir"
code=$(run_install good "$work/pfx-good")
if [ "$code" = 0 ] && [ -x "$work/pfx-good/bin/opencraysec" ]; then
	ok "a verified release installs the program"
else
	bad "a verified release installs the program" "exit $code: $(cat "$work/err")"
fi
missing=
for f in $doc_files; do
	[ -f "$work/pfx-good/$doc_subdir/$f" ] || missing="$missing $f"
done
if [ -z "$missing" ]; then
	ok "every licence file in scripts/doc-files.sh lands under $doc_subdir"
else
	bad "licence files missing after install:$missing"
fi
if no_staging_left "$work/pfx-good/bin"; then ok "no staging directory is left behind"; else bad "a staging directory was left in bin/"; fi
if "$work/pfx-good/bin/opencraysec" --version | grep -q '^opencraysec '; then ok "the installed program runs"; else bad "the installed program does not run"; fi

# --- uninstall is the other half ---------------------------------------------
mkdir -p "$work/pfx-good/share/doc/other-tool"
echo keep > "$work/pfx-good/share/doc/other-tool/README"
code=$(run_uninstall "$work/pfx-good")
if [ "$code" = 0 ] && [ ! -e "$work/pfx-good/bin/opencraysec" ] && [ ! -e "$work/pfx-good/$doc_subdir" ]; then
	ok "uninstall removes the program and its licence directory"
else
	bad "uninstall left files behind" "exit $code: $(cat "$work/uerr")"
fi
if [ -f "$work/pfx-good/share/doc/other-tool/README" ]; then ok "uninstall keeps files that are not ours"; else bad "uninstall removed someone else's files"; fi
code=$(run_uninstall "$work/pfx-good")
if [ "$code" = 0 ] && grep -q 'nothing to remove' "$work/uout"; then ok "uninstalling twice is harmless"; else bad "second uninstall misbehaved" "exit $code: $(cat "$work/uout")"; fi
code=$(run_uninstall "$work/pfx-good/bin")
if [ "$code" = 2 ]; then ok "uninstall refuses a prefix that ends in /bin"; else bad "uninstall accepted --prefix .../bin" "exit $code"; fi

# --- checksum handling -------------------------------------------------------
echo "tampered" >> "$work/serve-good/$asset_name"
code=$(run_install good "$work/pfx-mismatch")
if [ "$code" != 0 ] && nothing_installed "$work/pfx-mismatch" && grep -q 'checksum mismatch' "$work/err"; then
	ok "a checksum mismatch installs nothing"
else
	bad "a checksum mismatch was not refused" "exit $code: $(cat "$work/err")"
fi
pack good opencraysec "$doc_subdir"

code=$(STUB_NO_CHECKSUM=1 run_install good "$work/pfx-nosum")
if [ "$code" != 0 ] && nothing_installed "$work/pfx-nosum" && grep -q 'no checksum published' "$work/err"; then
	ok "a missing checksum installs nothing"
else
	bad "a missing checksum was not refused" "exit $code: $(cat "$work/err")"
fi
code=$(STUB_EMPTY_CHECKSUM=1 run_install good "$work/pfx-emptysum")
if [ "$code" != 0 ] && nothing_installed "$work/pfx-emptysum" && grep -q 'is empty' "$work/err"; then
	ok "an empty checksum installs nothing"
else
	bad "an empty checksum was not refused" "exit $code: $(cat "$work/err")"
fi
code=$(STUB_NO_CHECKSUM=1 run_install good "$work/pfx-insecure" --insecure)
if [ "$code" = 0 ] && [ -x "$work/pfx-insecure/bin/opencraysec" ] && grep -q 'unverified' "$work/err"; then
	ok "--insecure installs an unverified asset, and says so"
else
	bad "--insecure did not behave" "exit $code: $(cat "$work/err")"
fi

# --- what is in the archive --------------------------------------------------
build_asset extra
echo evil > "$work/stage-extra/evil"
pack extra opencraysec evil "$doc_subdir"
code=$(run_install extra "$work/pfx-extra")
if [ "$code" != 0 ] && nothing_installed "$work/pfx-extra" && grep -q 'unexpected member' "$work/err"; then
	ok "an archive with an unexpected member installs nothing"
else
	bad "an unexpected archive member was not refused" "exit $code: $(cat "$work/err")"
fi

build_asset noprog
pack noprog "$doc_subdir"
code=$(run_install noprog "$work/pfx-noprog")
if [ "$code" != 0 ] && nothing_installed "$work/pfx-noprog"; then
	ok "an archive without the program installs nothing"
else
	bad "an archive without the program was accepted" "exit $code"
fi

build_asset link
rm -f "$work/stage-link/$doc_subdir/LICENSE"
ln -s /etc/passwd "$work/stage-link/$doc_subdir/LICENSE"
pack link opencraysec "$doc_subdir"
code=$(run_install link "$work/pfx-link")
if [ "$code" != 0 ] && nothing_installed "$work/pfx-link" && grep -q 'symlink' "$work/err"; then
	ok "a licence file that is a symlink is refused before the program is installed"
else
	bad "a symlinked licence file was accepted" "exit $code: $(cat "$work/err")"
fi

build_asset broken
printf '#!/bin/sh\nexit 1\n' > "$work/stage-broken/opencraysec"
chmod 0755 "$work/stage-broken/opencraysec"
pack broken opencraysec "$doc_subdir"
code=$(run_install broken "$work/pfx-broken")
if [ "$code" != 0 ] && [ ! -e "$work/pfx-broken/bin/opencraysec" ] && no_staging_left "$work/pfx-broken/bin" && grep -q 'not runnable' "$work/err"; then
	ok "a program that does not run is refused and its staging directory removed"
else
	bad "a broken program was installed" "exit $code: $(cat "$work/err")"
fi

# --- an existing installation survives a failed upgrade ----------------------
mkdir -p "$work/pfx-keep/bin"
printf '#!/bin/sh\necho "opencraysec 0.0.1"\n' > "$work/pfx-keep/bin/opencraysec"
chmod 0755 "$work/pfx-keep/bin/opencraysec"
code=$(run_install broken "$work/pfx-keep")
if [ "$code" != 0 ] && "$work/pfx-keep/bin/opencraysec" --version | grep -q '0.0.1'; then
	ok "a failed upgrade leaves the previous installation in place"
else
	bad "a failed upgrade damaged the previous installation"
fi

# --- the release archive check agrees with the installer ------------------------
checker="$here/check-release-archive.sh"
check_archive() { sh "$checker" "$1" >"$work/cout" 2>"$work/cerr" && echo 0 || echo $?; }
code=$(check_archive "$work/serve-good/$asset_name")
if [ "$code" = 0 ]; then ok "the archive check accepts a well-formed release archive"; else bad "the archive check refused a good archive" "$(cat "$work/cerr")"; fi

# What bsdtar on macOS produces for a file with extended attributes.
build_asset appledouble
printf 'x' > "$work/stage-appledouble/._opencraysec"
pack appledouble opencraysec ._opencraysec "$doc_subdir"
code=$(check_archive "$work/serve-appledouble/$asset_name")
if [ "$code" = 1 ] && grep -q '\._opencraysec' "$work/cerr"; then
	ok "the archive check refuses an AppleDouble member"
else
	bad "an AppleDouble member was not refused by the archive check" "exit $code: $(cat "$work/cerr")"
fi
code=$(run_install appledouble "$work/pfx-appledouble")
if [ "$code" != 0 ] && nothing_installed "$work/pfx-appledouble" && grep -q 'unexpected member' "$work/err"; then
	ok "install.sh refuses the same archive, which is why the check exists"
else
	bad "install.sh accepted an AppleDouble member" "exit $code: $(cat "$work/err")"
fi

build_asset appledoc
printf 'x' > "$work/stage-appledoc/$doc_subdir/._LICENSE"
pack appledoc opencraysec "$doc_subdir"
code=$(check_archive "$work/serve-appledoc/$asset_name")
if [ "$code" = 1 ] && grep -q 'AppleDouble' "$work/cerr"; then ok "the archive check refuses an AppleDouble licence file"; else bad "an AppleDouble licence file passed the archive check" "exit $code: $(cat "$work/cerr")"; fi

code=$(check_archive "$work/serve-extra/$asset_name")
if [ "$code" = 1 ] && grep -q 'unexpected member: evil' "$work/cerr"; then ok "the archive check names an unexpected member"; else bad "an unexpected member passed the archive check" "exit $code: $(cat "$work/cerr")"; fi
code=$(check_archive "$work/serve-noprog/$asset_name")
if [ "$code" = 1 ] && grep -q "exactly one 'opencraysec'" "$work/cerr"; then ok "the archive check refuses an archive with no program"; else bad "an archive with no program passed the check" "exit $code: $(cat "$work/cerr")"; fi
code=$(sh "$checker" >/dev/null 2>&1 && echo 0 || echo $?)
if [ "$code" = 2 ]; then ok "the archive check needs an argument"; else bad "the archive check accepted no argument" "exit $code"; fi

# --- every platform gets the asset built for it --------------------------------
# $1 = OS, $2 = uname -m, $3 = 1 on Apple Silicon hardware, $4 = the asset that must be fetched.
# The curl stub serves only that asset, so asking for any other one fails the install.
check_platform() {
	os=$1 arch=$2 silicon=$3 want=$4
	case_name="plat-$want"
	rm -rf "$work/serve-$case_name"
	mkdir -p "$work/serve-$case_name"
	cp "$work/serve-good/$asset_name" "$work/serve-$case_name/$want"
	(cd "$work/serve-$case_name" && sha_of "$want" > "$want.sha256")
	code=$(STUB_OS=$os STUB_ARCH=$arch STUB_APPLE_SILICON=$silicon STUB_SERVE_ASSET=$want \
		run_install "$case_name" "$work/pfx-$case_name")
	if [ "$code" = 0 ] && [ -x "$work/pfx-$case_name/bin/opencraysec" ]; then
		ok "$os $arch (Apple Silicon hardware: $silicon) installs $want"
	else
		bad "$os $arch did not install $want" "exit $code: $(cat "$work/err")"
	fi
}
check_platform Linux x86_64 0 opencraysec-x86_64-unknown-linux-musl.tar.gz
check_platform Linux aarch64 0 opencraysec-aarch64-unknown-linux-musl.tar.gz
check_platform Linux arm64 0 opencraysec-aarch64-unknown-linux-musl.tar.gz
check_platform Darwin arm64 1 opencraysec-aarch64-apple-darwin.tar.gz
check_platform Darwin x86_64 0 opencraysec-x86_64-apple-darwin.tar.gz
# A shell under Rosetta says x86_64 on an Apple Silicon Mac: the native binary is the right one.
check_platform Darwin x86_64 1 opencraysec-aarch64-apple-darwin.tar.gz

# The wrong platform's asset is never accepted: a Mac that can only be served the Linux asset gets
# a 404 from the stub, so nothing is installed.
code=$(STUB_OS=Darwin STUB_ARCH=arm64 STUB_APPLE_SILICON=1 run_install good "$work/pfx-wrong-os" || true)
if nothing_installed "$work/pfx-wrong-os"; then ok "a Mac is never handed the Linux binary"; else bad "a Mac got the Linux binary"; fi

# --- arguments and environment -----------------------------------------------
: > "$work/calls.log"
STUB_LOG="$work/calls.log" run_install good "$work/pfx-ver" --version v1.2.3 >/dev/null
if grep -q 'releases/download/v1.2.3/' "$work/calls.log" && grep -q -- "--proto =https" "$work/calls.log" && grep -q -- '--tlsv1.2' "$work/calls.log"; then
	ok "--version selects the release URL, and curl is pinned to https and TLS 1.2"
else
	bad "unexpected curl invocation" "$(cat "$work/calls.log")"
fi
: > "$work/calls.log"
STUB_LOG="$work/calls.log" run_install good "$work/pfx-latest" >/dev/null
if grep -q 'releases/latest/download/' "$work/calls.log"; then ok "without --version the newest release is fetched"; else bad "latest URL not used" "$(cat "$work/calls.log")"; fi

code=$(run_install good "$work/pfx-badver" --version '-x')
if [ "$code" = 2 ]; then ok "a --version that looks like an option is refused"; else bad "a dash-leading --version was accepted" "exit $code"; fi
code=$(run_install good "$work/pfx-badver" --version 'v1/../../x')
if [ "$code" = 2 ]; then ok "a --version that walks the URL is refused"; else bad "a path-walking --version was accepted" "exit $code"; fi
code=$(OPENCRAYSEC_REPO='evil' run_install good "$work/pfx-badrepo")
if [ "$code" = 2 ]; then ok "OPENCRAYSEC_REPO must be owner/name"; else bad "a malformed OPENCRAYSEC_REPO was accepted" "exit $code"; fi
code=$(OPENCRAYSEC_REPO='a/b/c' run_install good "$work/pfx-badrepo")
if [ "$code" = 2 ]; then ok "OPENCRAYSEC_REPO with too many parts is refused"; else bad "owner/name/extra was accepted" "exit $code"; fi

code=$(run_install good "$work/x/bin")
if [ "$code" = 2 ] && [ ! -e "$work/x" ]; then ok "a prefix ending in /bin is refused without creating anything"; else bad "a prefix ending in /bin was accepted" "exit $code"; fi
code=$(run_install good /usr)
if [ "$code" = 2 ]; then ok "a prefix that would write /usr/bin is refused"; else bad "--prefix /usr was accepted" "exit $code"; fi
code=$(run_install good "")
if [ "$code" = 2 ]; then ok "an empty --prefix is refused"; else bad "an empty --prefix was accepted" "exit $code"; fi
code=$(env -i PATH="$stub_dir:$PATH" sh "$installer" --bogus >/dev/null 2>&1 && echo 0 || echo $?)
if [ "$code" = 2 ]; then ok "an unknown argument is a usage error"; else bad "an unknown argument was accepted" "exit $code"; fi
code=$(env -i PATH="$stub_dir:$PATH" sh "$installer" --help >/dev/null 2>&1 && echo 0 || echo $?)
if [ "$code" = 0 ]; then ok "--help exits cleanly"; else bad "--help failed" "exit $code"; fi
code=$(env -i PATH="$stub_dir:$PATH" sh "$installer" --prefix >/dev/null 2>&1 && echo 0 || echo $?)
if [ "$code" = 2 ]; then ok "a flag without its value is a usage error"; else bad "a valueless --prefix was accepted" "exit $code"; fi

# --- DESTDIR staging -----------------------------------------------------------
code=$(run_install good /opt/tools --destdir "$work/dest")
if [ "$code" = 0 ] && [ -x "$work/dest/opt/tools/bin/opencraysec" ] && [ -f "$work/dest/opt/tools/$doc_subdir/LICENSE" ]; then
	ok "--destdir stages under DESTDIR"
else
	bad "--destdir did not stage" "exit $code: $(cat "$work/err")"
fi

# --- the script is safe to pipe -------------------------------------------------
if [ "$(tail -n 1 "$installer")" = 'main "$@"' ]; then ok "main runs on the last line only, so a truncated download does nothing"; else bad "the last line of install.sh is not the call to main"; fi
if sh -n "$installer" && sh -n "$uninstaller"; then ok "both scripts parse as POSIX sh"; else bad "a script does not parse"; fi

if [ "$fail" -ne 0 ]; then
	echo "install-sh.test: FAILED" >&2
	exit 1
fi
echo "install-sh.test: passed"
