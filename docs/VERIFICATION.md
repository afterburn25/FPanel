# Verification checklist

Run `./scripts/verify.sh`.

The Go tests currently cover:

- missing agent authentication rejected with HTTP 401;
- authenticated health request succeeds;
- non-allow-listed service operation rejected;
- allow-listed restart succeeds and records actor-aware audit evidence;
- hosting account/site/PHP lifecycle;
- traversal-like domain rejection;
- safe file write/list and path traversal rejection;
- database/DNS/certificate/backup/mailbox/reseller models;
- SFTP/firewall/application models;
- 2.0 fleet, 3.0 cloud and 5.0 fabric simulations explicitly return simulation markers;
- 4.0 automated provisioning simulation completes account/site/DNS/certificate steps.

Browser/control-plane validation includes PHP syntax checks and JavaScript syntax parsing. Production release certification will require real-host integration tests and cannot be satisfied by mock-mode tests alone.
