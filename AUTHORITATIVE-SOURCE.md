# Authoritative Source of Truth

Repository: `afterburn25/FPanel`
Branch: `main`

Beginning with the user-accepted **Privora Panel 5.0.0-dev.7.0 Rev5 Rev9** build on 2026-10-25, this repository's `main` branch is the authoritative development source of truth for Privora Panel / FPanel.

## Accepted baseline

- Product version: `5.0.0-dev.7.0`
- Accepted release: **Rev5 Rev9**
- Controlled release files: **337**
- `FULL-CORE-MANIFEST.json` SHA-256: `f94d7e270f915be75b5f3c4f491fd1094d78911ba3d276cf6fa6bc955457aac3`
- Precompiled Agent SHA-256: `5d38e03a6d6a0640b43680192ff90a5de3e29246efc8b11ac7b4ac697929e54a`
- HostAdapter certification binary SHA-256: `9746e455bac06fd86fe489ecf0e024420d64a777ce74c42154bfce0f986f0671`
- API certification binary SHA-256: `9d674a6d2c18733b7f1c303118030a1afe226958fbb9699e4e1d0f951c61d995`

Rev5 Rev9 preserves the accepted Rev5 Rev8 Dovecot virtual-mail renderer/authentication repair and fixes the remaining secure-mail Postfix validation path so live `postfix check` runs through Privora's narrowly scoped isolated-root maintenance helper instead of inside the hardened long-running Agent.

## Source / artifact policy

- `main` is authoritative for source, tests, release notes, roadmap, and current implementation direction.
- Do not replace `main` with an older retained package, stale chat artifact, or stale local checkout.
- `FULL-CORE-MANIFEST.json` records the exact accepted runtime package contents.
- Large precompiled runtime binaries under `dist/` are release artifacts. Their accepted SHA-256 values are recorded above and in the corresponding `.sha256` files. GitHub source verification rebuilds/tests from source rather than treating an unverified binary as authoritative.
- A future release is not accepted/live merely because it is committed to GitHub; user installation and acceptance remain required.

## Rev5 Rev9 acceptance

The user confirmed Rev5 Rev9 installed successfully after Rev5 Rev8 had already validated:

- Dovecot and Postfix active;
- Dovecot `passwd-file` virtual authentication;
- successful `doveadm user` resolution for `admin@privategather.com` and `admin@cajunwebpro.com`;
- canonical multiline `/etc/dovecot/conf.d/99-privora-mail.conf` rendering;
- isolated-root Postfix validation without weakening Agent hardening.
