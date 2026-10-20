# The files that have to travel with the program.
#
# The MIT License requires its copyright and permission notice to accompany every copy or
# substantial portion of the software, and the licences of the crates compiled into the
# binary (Apache-2.0, ISC, BSD-3-Clause, Zlib, Unicode-3.0, CDLA-Permissive-2.0) require
# their own texts and attributions to travel with a redistribution. A binary in $BINDIR is a
# redistribution, so the licences cannot live only in the repository: install.sh,
# `make install` and the release tarball all put these under $PREFIX/share/doc/opencraysec,
# next to what they are about.
#
# This file is the single list. install.sh checks the tar members against it, uninstall.sh
# removes exactly it, the Makefile installs and removes it, and the release workflow tars
# exactly it -- so a licence file cannot quietly stop shipping in one of those and keep
# shipping in the others.
#
# Sourced, not executed, so the callers choose the interpretation. POSIX sh only, so the
# release workflow and the Makefile can read it too.
#
#   OPENCRAYSEC_DOC_SUBDIR   where under $PREFIX the files land
#   OPENCRAYSEC_DOC_FILES    newline-separated paths, relative to the repository root

OPENCRAYSEC_DOC_SUBDIR='share/doc/opencraysec'

# Our own licence, the attribution notice, the human-readable inventory, then the texts and
# the machine-readable inventory that inventory points at.
OPENCRAYSEC_DOC_FILES='LICENSE
NOTICE
THIRD-PARTY-LICENSES.md
licenses/MIT.txt
licenses/Apache-2.0.txt
licenses/ISC.txt
licenses/BSD-3-Clause.txt
licenses/Zlib.txt
licenses/Unicode-3.0.txt
licenses/CDLA-Permissive-2.0.txt
licenses/deps.tsv'
