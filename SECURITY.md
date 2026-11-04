# Privora Panel security model

Privora Panel controls high-value infrastructure. The browser must never become a root shell with a nicer skin.

## Enforced now

1. Browser/PHP exposes no arbitrary root-command endpoint.
2. Privileged work maps to typed Go-agent routes and allow-listed operations.
3. Local panel→agent requests are HMAC-SHA256 signed using method, URI, timestamp, nonce and body digest.
4. Freshness windows and nonce replay rejection are enforced.
5. Privileged audit records carry actor/request IDs and form a SHA-256 hash chain.
6. Host mutations require both `--host-mutations` and a **machine-bound certification artifact** whose `/etc/machine-id` hash matches the current server.
7. Real account file operations use descriptor-relative no-follow traversal; symlink/traversal escape is rejected even though the agent is privileged.
8. Linux hosting homes use a root-owned SFTP chroot root; customer write access is limited to owned subdirectories.
9. Browser passwords use Argon2id; sessions are HttpOnly/SameSite=Strict with inactivity expiry.
10. Browser mutations require CSRF + server-side RBAC/account ownership.
11. TOTP MFA secrets are encrypted at rest.
12. External API keys are returned once, persisted by digest and enforced by fixed scope mappings.
13. Database/mail/SFTP generated credentials are returned only in the successful create response and are not persisted as plaintext by Privora resource state.
14. DNS/Nginx/SSH/firewall mutations perform syntax/preflight validation and use rollback intent where implemented.
15. 2.0 mTLS replay state, node enrollment/rotation/revocation records, 3.0 lifecycle intents, 4.0 order state and 5.0 placements survive restart.
16. The internal provider-secret vault uses AES-256-GCM authenticated encryption and versioned rotation.
17. The billing ledger is double-entry and hash-chained; unbalanced/tampered records fail verification.
18. 5.0 failure intent requires fresh majority peer evidence at one epoch; split/minority evidence does not trigger failover.

## Still required before production 1.0

- live adapter certification on each supported Ubuntu/Debian target for PHP-FPM, DB, DNS, ACME, mail, SFTP, nftables, quota and cgroups;
- complete account/site/service deletion/rollback and restore drills;
- real encrypted off-host backup retention and granular restore;
- signed installer/update verification using offline-trusted release keys;
- passkeys/recovery codes and step-up reauthentication for destructive actions;
- systemd/capability/seccomp confinement for operation-specific executors;
- penetration testing, fuzzing, dependency review, load, disk-full, kill/restart and destructive failure injection.

## Still required before production 2.0+

- production CA/HSM or equivalent custody, enrollment approval, rotation and revocation distribution;
- remote convergence tests under network loss/reordering/partition;
- cloud-provider credential injection/rotation without browser exposure;
- verified payment-provider webhooks and reconciliation;
- actual distributed replication/consensus/fencing authority before automatic multi-region failover;
- live DNS/load-balancer traffic routing and chaos/DR certification.

## dev.5 installer/update trust boundary

The fresh-VPS installer is root by design, so its supply-chain and rollback boundaries are treated as privileged security controls:

- network release acquisition is HTTPS-only and requires SHA-256 plus RSA signature verification before extraction;
- production release hosting must replace the checked-in development public key with an offline/HSM-controlled production signing keypair (private key is never shipped to servers);
- update jobs are typed (`security` or `full`) and launched by the root agent only when the machine-bound `privora-updater` adapter is certified;
- automatic maintenance is policy controlled; major runtime/database upgrades remain manual by default;
- pre-update state/configuration is snapshotted before package or Privora promotion;
- Privora releases are staged privately and atomically promoted only after dependency/configuration/migration preflight;
- post-promotion failure invokes rollback to the previous release and health checks it;
- the web control plane runs as `privora-panel`, while the privileged Go agent remains root and exposes only the protected typed Unix-socket API.
