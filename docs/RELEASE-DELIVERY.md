# Privora Release Delivery and Signing

Privora uses a split trust model. Installed VPS nodes contain public verification keys only. Production private keys must stay off-host, preferably in an HSM or an isolated offline release-signing job.

## Core release chain

`scripts/build-signed-release.sh` builds and tests the Go agent from source, creates a reproducible `.tar.zst`, emits SHA-256 metadata, signs both the archive and its JSON metadata, and produces a signed channel pointer plus compatibility `privora-panel-current.tar.zst` aliases.

Set `PRIVORA_RELEASE_SIGNING_KEY` only in the isolated signing environment. Do not copy that key into a Privora VPS, repository, release ZIP, CI artifact, or web root.

## Publication layout

```
/releases/stable/current.json
/releases/stable/current.json.sig
/releases/stable/privora-panel-current.tar.zst
/releases/stable/privora-panel-current.tar.zst.sha256
/releases/stable/privora-panel-current.tar.zst.sig
/releases/stable/<version>/privora-panel-<version>.tar.zst
...
```

Publication should be append-only for immutable version directories. The channel alias may advance only after signature verification and release certification.

## Production key ceremony gate

This source tree deliberately does not contain a production private key. Before public launch: generate the production key under controlled custody, replace the development public verification key in the bootstrap/update channel, dual-review the fingerprint, publish the fingerprint out-of-band, and archive a recovery/revocation procedure.
