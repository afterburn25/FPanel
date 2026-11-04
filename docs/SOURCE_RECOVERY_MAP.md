# Privora Panel / FPanel recovery source map

**Reviewed on 2026-11-03.** This document records actual source locations; it does not certify a latest release.

## Repository evidence

- `afterburn25/FPanel` `main`: README-only. Development branch `dev-6.57-pcc-ppanel-routing` has CI workflows, source checkpoint documents, upgrade certifications and scripts.
- `afterburn25/privora-os` `main`: retains versioned Privora OS release/source **ZIP archives**, including multiple 4.0 RC source bundles. These files are not equivalent to the later FPanel 5.0.0-dev.6.7x source.
- A preserved 2026-08-21 validation report records `privora-6.72-to-6.77-direct-upgrade.tar.gz`, version 5.0.0-dev.6.77; SHA-256 `f8dd4ac1f124a9a7ff29d2dadf009e103b87adeae03e5055a70ea33ef868d3f1`. The source archive itself has **not yet been recovered** here.
- Local VPS and hosting panel deployment may contain additional source or a working tree, but was **not accessed in this audit**.

## What is preserved by this recovery branch

- The 6.57/6.58 GitHub CI and routing checks
- 6.57–6.66 checkpoint and DNS-related documentation
- `scripts/reconcile-panel-path-aliases.py` and associated test fixture
- Release trust metadata and a public verification key

The current branch **does not contain a complete panel runtime**, and any newer local code must be compared before implementation resumes.

## Recovery process

1. Identify the most recent complete code and full source on the Privora VPS or archived release.
2. Capture a read-only archive and exact SHA-256, excluding private keys, tokens, credentials, databases and runtime tenant data.
3. Verify source provenance and reintroduce to `FPanel` on a separate feature/recovery branch.
4. Run PHP/Go/JavaScript builds, permission/security gates and certified release tests before considering merge or deployment.
5. Preserve prior versions and keep production changes explicitly authorized.

Repository links: [FPanel](https://github.com/afterburn25/FPanel) and [privora-os](https://github.com/afterburn25/privora-os).
