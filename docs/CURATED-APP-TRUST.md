# Curated Application Trust Chain

Privora application packages use a signing key that is separate from the Privora core-release signing key. The VPS stores only `install/app-release-public-key.pem`.

The signed `privora-app-release-manifest-v1` authorizes an exact application template/version/source URL/SHA-256/archive format/size ceiling/bootstrap mode. The root agent refuses unsigned or modified manifests, non-HTTPS sources, digest mismatches, oversized downloads, path traversal, symlinks, hardlinks, devices, and non-empty publish targets.

Production app-catalog private-key custody must be independent from the panel core-release key. The checked-in public key is development-only until the production app-catalog key ceremony is complete.

Current execution modes:
- `wordpress`: database provisioning, `wp-config.php`, atomic publish, and non-interactive WordPress bootstrap.
- `joomla`: database provisioning, atomic publish and headless Joomla CLI bootstrap; secrets are supplied through stdin rather than command-line arguments.
- `guided-web`: verified source/database/publish with the application left at its own first-run setup screen.
- `none`: verified publish only.

Every additional fully automated bootstrap mode must receive its own application-specific tests before promotion.

Catalog promotion rule:
- every application template must have exactly one release marked `"current": true`; Privora rejects signed catalogs that have zero or multiple current releases for a template.
- a version may still be requested explicitly, but an unversioned one-click install resolves only to the signed current release.
- full/web VPS bootstrap requires the signed catalog by default; if it cannot be downloaded or verified, one-command installation fails closed instead of silently disabling the installer.
