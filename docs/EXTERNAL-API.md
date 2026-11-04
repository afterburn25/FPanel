# External API and CLI — 5.0.0-dev.6

The external API is exposed by `panel/public/external-api.php`. It authenticates a scoped `prv_...` API key, verifies its digest through the protected local agent, then maps only known resources to typed agent operations.

API keys are created with scopes such as:

- `health.read`
- `accounts.read`, `accounts.write`
- `sites.read`, `sites.write`
- `resources.read`
- `backups.write`
- `dns.write`
- `ssl.write`

The key secret is shown only in the create response; the agent persists a SHA-256 digest, prefix, name, scopes and status.

CLI example:

```bash
export PRIVORA_API_URL='https://panel.example.com/external-api.php'
export PRIVORA_API_KEY='prv_...'
./cli/privora health
./cli/privora accounts
./cli/privora sites
./cli/privora horizons
```

The API does not provide a generic URL/path forwarding parameter. Adding a new external operation requires an explicit route and scope mapping.
