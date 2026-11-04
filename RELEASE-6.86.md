# Privora Panel 5.0.0-dev.6.86 — Editable Subdomain Document Roots & Shared-Root Delete Safety

Prepared development candidate. Do not treat as live/accepted until installed and verified on the VPS.

## Subdomain creation
- Create Subdomain now shows the resolved default document root before submission.
- The document-root field is editable in both PCC and PPanel.
- **Use default root** restores `/home/<account>/domains/<subdomain>/public`.
- **Use parent domain root** points the subdomain to the parent website's current document root.
- Custom roots must remain inside the same hosting account's `/home/<account>/domains` tree.
- Existing directories elsewhere inside the account may be intentionally shared; new custom directories are only auto-created inside the subdomain's own domain tree.
- Existing shared content is never overwritten or recursively re-owned during subdomain provisioning.

## Delete safety
- A dedicated subdomain root is eligible for automatic cleanup when the subdomain is deleted.
- A parent-domain root, a root shared with another managed/live site, or a custom root outside the subdomain's own domain tree is classified as shared content.
- Shared content is always preserved when deleting the subdomain; Privora removes only the subdomain vhost/DNS/state.
- The browser, PHP API bridge, Agent, and HostAdapter all retain independent safety checks.
- HostAdapter refuses recursive deletion if the configured root is not inside the subdomain's own domain tree.

## Security
- Absolute paths only.
- Document roots cannot escape the hosting account domains tree.
- Existing symlinks are resolved and rejected if they escape the account domains tree.
- The production installer remains fail-closed and uses precompiled Agent binaries.
