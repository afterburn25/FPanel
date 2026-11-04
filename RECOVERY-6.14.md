# dev.6.14 WHM uploaded Update Center recovery

This build adds the browser-managed Privora core update path. Existing dev.6.x VPS installations remain journal-compatible.

For the existing VPS, upload/extract this build and run the normal installer one final time from SSH:

```bash
PRIVORA_REQUIRE_APP_CATALOG=0 ./install/privora-install.sh \
  --source-dir "$(pwd)" \
  --mode full \
  --channel developer
```

Completed bootstrap, service and certification phases are skipped. The new `whm_update_center` phase refreshes only the privileged agent, Update Center/API/frontend, verifier/trust key and updater/rollback scripts, then reconciles PHP-FPM/Nginx.

After this phase passes, future signed Privora ZIPs can be installed from **Privora Admin → System Updates**:

1. Upload the signed Privora ZIP.
2. Privora validates structure, version, payload digest and RSA signature before installation is offered.
3. Enter the server root password. It is sent only to the local privileged agent and verified with PAM; it is never persisted or placed on a command line.
4. If the current WHM user has TOTP MFA enabled, enter the current six-digit authenticator code as well.
5. Privora issues a two-minute, one-use authorization scoped to that exact staged ZIP and starts the allow-listed updater.
6. The updater takes a protected snapshot, stages/migrates/validates the release, atomically promotes it, restarts only required services and runs health checks.
7. A failed promoted release automatically rolls back. Migration/validation failures before promotion restore the pre-update snapshot.

Only signed packages trusted by the locally installed Privora release public key are accepted. The offline release private key is never installed on a managed VPS.
