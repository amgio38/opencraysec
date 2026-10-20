## What and why

<!-- What does this change, and what problem does it solve? Link the issue if there is one. -->

## How it was checked

<!-- The commands you ran and what they showed. A bug fix should name the test that fails without it. -->

## Checklist

- [ ] `make preflight` passes locally (format, clippy with `-D warnings`, the whole test suite, layering, licence, installer, `cargo deny`, docs, and the 90% coverage gate).
- [ ] New behaviour has a test, and a bug fix has a test that fails without the fix.
- [ ] Matching logic was checked against real advisory data, not only hand-written fixtures.
- [ ] User-visible change is described in `CHANGELOG.md` under *Unreleased*.
- [ ] If a lockfile format or ecosystem was added: parser, version ordering, fix commands, purl and docs are all updated.
- [ ] No secrets, personal paths, private data or unpublished vulnerability details in the diff, comments or commit messages.
- [ ] Comments and documentation are in English.

By contributing you agree to follow the [Code of Conduct](../CODE_OF_CONDUCT.md).
