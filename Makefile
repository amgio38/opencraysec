# Throttle: this machine may be shared. Override on the command line if needed.
JOBS ?= 8
export RUST_TEST_THREADS ?= 4

# Where cargo writes build output. Honors CARGO_TARGET_DIR the way cargo does, so
# `make install` and `make release-static` keep working when it is set.
TARGET_DIR ?= $(or $(CARGO_TARGET_DIR),target)

.PHONY: check fmt-check clippy test layering deny licenses install-test docs-check coverage ci preflight
check:
	cargo check --workspace --all-targets -j $(JOBS)
fmt-check:
	cargo fmt --all -- --check
clippy:
	cargo clippy --workspace --all-targets -j $(JOBS) -- -D warnings
test:
	cargo test --workspace -j $(JOBS)
layering:
	@scripts/check-layering.sh
	@scripts/check-layering.test.sh
licenses:
	@scripts/check-licenses.sh
	@python3 scripts/gen-third-party-licenses.py --check

# The installer's own behaviour, with the network stubbed out. install.sh is mostly decisions
# about *failure* -- an unverified or mismatched release asset must not reach $BINDIR -- and
# those are exactly the paths a syntax check and a read-through miss.
install-test:
	@scripts/install-sh.test.sh

# Line coverage: every crate and every source file at 90% or better. Needs cargo-llvm-cov and the
# llvm-tools component (`cargo install cargo-llvm-cov --locked`, `rustup component add
# llvm-tools-preview`).
coverage:
	@scripts/check-coverage.sh

# The licence policy in deny.toml, enforced. This target does not install the tool:
# `cargo install cargo-deny --locked`, or rely on CI, which installs it with
# taiki-e/install-action and runs it on every push.
#
# It is in `ci` rather than left as a target nobody runs, because a policy file with no gate is a
# comment.
#
# A machine without cargo-deny is a hard stop by default: skipping silently is the fail-open this
# is meant to end. On a machine that cannot install it, say so out loud:
#
#   make ci ALLOW_MISSING_CARGO_DENY=1
#
# ...which prints a warning and continues. CI never needs that escape hatch.
DENY_FLAGS ?= --all-features check licenses bans advisories sources
ALLOW_MISSING_CARGO_DENY ?= 0

deny:
	@if command -v cargo-deny >/dev/null 2>&1; then \
		cargo deny $(DENY_FLAGS); \
	elif [ "$(ALLOW_MISSING_CARGO_DENY)" = 1 ]; then \
		echo "make deny: WARNING cargo-deny is not installed, so deny.toml was NOT checked." >&2; \
		echo "make deny: install it with 'cargo install cargo-deny --locked'." >&2; \
	else \
		echo "make deny: cargo-deny is not installed, so deny.toml was NOT checked." >&2; \
		echo "make deny: install it with 'cargo install cargo-deny --locked', or" >&2; \
		echo "make deny: re-run as 'make ci ALLOW_MISSING_CARGO_DENY=1' to accept that." >&2; \
		exit 1; \
	fi

docs-check:
	@scripts/check-docs.sh

ci: fmt-check clippy test layering docs-check licenses install-test deny

# Run before every push: exactly what CI runs, on the tree being pushed (docs/RELEASING.md).
# `make ci` is the quick inner loop; `make preflight` is the gate (it also runs coverage).
preflight:
	bash scripts/preflight.sh

# --- release ----------------------------------------------------------------
# One self-contained Linux binary. The musl target is required; this target only checks for it and
# prints the install command, it never installs. The TLS stack compiles a little C, so a musl C
# compiler is needed too (Debian/Ubuntu: `apt install musl-tools`).
MUSL_TARGET ?= x86_64-unknown-linux-musl
DIST        ?= dist

.PHONY: release-static
release-static:
	@command -v rustup >/dev/null 2>&1 || { \
		echo "error: rustup is required to check for the $(MUSL_TARGET) target" >&2; exit 1; }
	@rustup target list --installed | grep -qx '$(MUSL_TARGET)' || { \
		echo "error: the $(MUSL_TARGET) target is not installed" >&2; \
		echo "       install it with: rustup target add $(MUSL_TARGET)" >&2; exit 1; }
	cargo build --release --locked --target $(MUSL_TARGET) -j $(JOBS) -p opencraysec-cli
	mkdir -p $(DIST)
	rm -f $(DIST)/opencraysec
	cp $(TARGET_DIR)/$(MUSL_TARGET)/release/opencraysec $(DIST)/opencraysec
	@file "$(DIST)/opencraysec" | grep -Eq 'statically linked|static-pie' || { \
		echo "error: $(DIST)/opencraysec is not a static executable" >&2; file "$(DIST)/opencraysec" >&2; exit 1; }
	@$(DIST)/opencraysec --version

# --- install ----------------------------------------------------------------
# `make install` builds the program in release mode and copies it into
# $(DESTDIR)$(PREFIX)/bin. PREFIX defaults to ~/.local, so a plain install puts it on the PATH of a
# user-local setup. DESTDIR is the usual staging prefix for packagers; it is prepended, never
# substituted.
#
#   make install                     -> ~/.local/bin/opencraysec
#   make install PREFIX=/usr/local   -> /usr/local/bin/opencraysec
#   make install DESTDIR=/tmp/stage  -> /tmp/stage$(PREFIX)/bin/opencraysec
#
# The licence files go to $(PREFIX)/share/doc/opencraysec, taken from the single list in
# scripts/doc-files.sh and removed by `make uninstall` with the program.
#
# The program is staged in a `mktemp -d` directory inside the destination, not at a name derived
# from the pid: anything able to write to the destination could predict such a name, leave a
# symlink there, and have `install` write through it. Same reasoning, and the same fix, as
# scripts/install.sh.
PREFIX  ?= $(HOME)/.local
BINDIR  ?= $(PREFIX)/bin
DESTDIR ?=

# The licence files that have to travel with the program, from the single list in
# scripts/doc-files.sh. `make install` is by definition run in a checkout, so unlike
# scripts/install.sh it can read that file.
DOC_SUBDIR := share/doc/opencraysec
DOC_SHARE  := $(DESTDIR)$(PREFIX)/share
DOCDIR    := $(DESTDIR)$(PREFIX)/$(DOC_SUBDIR)
DOC_FILES := $(shell . scripts/doc-files.sh 2>/dev/null && echo "$$OPENCRAYSEC_DOC_FILES")
ifeq ($(strip $(DOC_FILES)),)
$(error scripts/doc-files.sh did not list any licence files; `make install` would ship a binary with none)
endif

.PHONY: install uninstall install-docs uninstall-docs
install:
	cargo build --release --locked -j $(JOBS) -p opencraysec-cli
	@set -eu; \
	case "$(PREFIX)" in \
	  /bin|/sbin|*/bin|*/sbin) echo "error: PREFIX=$(PREFIX) ends in bin or sbin, so this would install into $(BINDIR)/bin; set PREFIX to the parent directory" >&2; exit 1;; \
	esac; \
	d="$(DESTDIR)$(BINDIR)"; \
	case "$$d" in ""|/bin|/sbin|/usr/bin|/usr/sbin) echo "error: refusing to install into '$$d' (set PREFIX, e.g. PREFIX=/usr/local, or DESTDIR when packaging)" >&2; exit 1;; esac; \
	install -d "$$d"; \
	s="$$(mktemp -d "$$d/.opencraysec.install.XXXXXX")"; a="$$s/opencraysec"; \
	trap 'rm -rf "$$s"' EXIT INT TERM; \
	install -m 0755 "$(TARGET_DIR)/release/opencraysec" "$$a"; \
	av=$$("$$a" --version 2>/dev/null | head -n1); av=$${av#* }; \
	if [ -z "$$av" ]; then echo "error: the staged binary does not run" >&2; exit 1; fi; \
	mv -f "$$a" "$$d/opencraysec"; \
	rm -rf "$$s"; \
	trap - EXIT INT TERM; \
	echo "installed opencraysec ($$av) into $$d"
	@$(MAKE) --no-print-directory install-docs
	@echo "next: opencraysec update --for . && opencraysec scan ."
	@echo "      claude mcp add opencraysec -- opencraysec mcp"

# Its own targets, so that installing the licence files and removing them again can be tested
# without building the workspace in release mode first. `install` and `uninstall` are the only
# callers; the licence set does not change shape between the two paths.
install-docs:
	@set -eu; for f in $(DOC_FILES); do \
	  test -f "$$f" || { echo "error: $$f is listed in scripts/doc-files.sh but not in this checkout" >&2; exit 1; }; \
	  install -d "$(DOCDIR)/$$(dirname "$$f")"; \
	  install -m 0644 "$$f" "$(DOCDIR)/$$f"; \
	done
	@echo "installed the licence files into $(DOCDIR)"

uninstall-docs:
	@case "$(DOCDIR)" in /share/doc/opencraysec) echo "error: refusing to remove $(DOCDIR)" >&2; exit 1;; esac
	@if [ -d "$(DOCDIR)" ] && [ ! -L "$(DOCDIR)" ]; then \
	  rm -rf "$(DOCDIR)"; \
	  rmdir "$(dir $(DOCDIR))" 2>/dev/null || true; \
	  rmdir "$(DOC_SHARE)" 2>/dev/null || true; \
	  echo "removed the licence files from $(DOCDIR)"; \
	fi

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/opencraysec"
	@$(MAKE) --no-print-directory uninstall-docs
	@echo "removed opencraysec from $(DESTDIR)$(BINDIR)"
