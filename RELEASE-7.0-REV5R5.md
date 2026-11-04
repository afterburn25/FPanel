# Privora Panel 5.0.0-dev.7.0 Rev5 Rev5 — AutoSSL Webroot Traversal & Mail Challenge Repair

Prepared development hotfix. Do not promote to accepted/live baseline until installed and user-approved.

## Live defect repaired

AutoSSL HTTP-01 could create a correct 0644 challenge token under a correct Nginx ACME location and still receive local/public HTTP 404. The preflight normalized only `.well-known`, `acme-challenge`, and the token itself. It did not restore the previously certified least-privilege Nginx execute-only ACL on protected parent directories leading to the webroot.

Affected layouts include:
- protected hosting roots under `/home/<account>/...`;
- dedicated mail ACME roots under `/etc/privora-mail/acme/<domain>`.

## Correction

- Preflight now computes ACL targets only for the two certified protected path families above.
- For each parent path, it grants only `u:www-data:--x` with `setfacl` so Nginx can traverse to the challenge without gaining directory-list/read access.
- `.well-known` and `acme-challenge` remain 0755 and the temporary token remains 0644.
- Other document-root families receive no new ACL mutation.
- Existing mail-specific ACME root selection remains unchanged.
- Explicit package/database fixes and PCC runtime-readiness fixes from Rev5 Rev4 are retained.
- Production update path uses precompiled runtime artifacts and does not invoke Go/compiler tooling.
