#!/bin/sh
# Refuses a release archive that scripts/install.sh would refuse.
#
#   scripts/check-release-archive.sh opencraysec-<target>.tar.gz
#
# The release workflow runs this on every archive before it is uploaded. install.sh only accepts
# the program plus the licence files under share/doc/opencraysec, and dies on any other member.
# That is the right thing for an installer, but it means an archive with one stray member is a
# release that no user can install, and nothing in the build would have noticed: this check puts
# the failure in the workflow instead of in front of the users.
#
# The case it exists for is macOS. bsdtar on macOS adds AppleDouble members (`._opencraysec`) for
# files that carry extended attributes unless COPYFILE_DISABLE=1 is set. The members are listed
# by `tar -tzf` but invisible in Finder, so they are easy to miss.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=scripts/doc-files.sh
. "$here/doc-files.sh"

[ "$#" -eq 1 ] || { echo "usage: check-release-archive.sh ARCHIVE" >&2; exit 2; }
archive=$1
[ -f "$archive" ] || { echo "check-release-archive: no such file: $archive" >&2; exit 2; }

listing=$(tar -tzf "$archive") || { echo "check-release-archive: cannot read $archive" >&2; exit 1; }

programs=0
bad=
old_ifs=$IFS
IFS='
'
set -f
for member in $listing; do
	m=${member#./}
	[ -n "$m" ] || continue
	case "$m" in
	opencraysec) programs=$((programs + 1)) ;;
	"$OPENCRAYSEC_DOC_SUBDIR" | "$OPENCRAYSEC_DOC_SUBDIR"/*)
		case "/$m/" in
		*/../*) bad="$bad\n  path walks upward: $m" ;;
		esac
		case "${m##*/}" in
		._*) bad="$bad\n  AppleDouble metadata: $m" ;;
		esac ;;
	*) bad="$bad\n  unexpected member: $m" ;;
	esac
done
set +f
IFS=$old_ifs

[ "$programs" -eq 1 ] || bad="$bad\n  expected exactly one 'opencraysec', found $programs"

if [ -n "$bad" ]; then
	printf 'check-release-archive: %s would be refused by install.sh:%b\n' "$archive" "$bad" >&2
	echo "check-release-archive: on macOS pack with COPYFILE_DISABLE=1" >&2
	exit 1
fi
echo "check-release-archive: $archive ok"
