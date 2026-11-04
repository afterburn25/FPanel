# Privora Panel 5.0.0-dev.6.72 — PPanel Workspace, Full File Manager & Account Analytics

Built from the certified 6.71 cumulative core after live PPanel review showed that the prior UX hotfixes did not sufficiently match a full hosting-control-panel workflow.

## PPanel layout recovery

- Removes both the temporary Software & Account Readiness strip and the remaining welcome/status banner so the PPanel home starts directly with the account/server rail and functional tool containers.
- Moves the existing information rail from the right to the left.
- Expands the rail with server hostname, OS, CPU, load, memory, uptime, shared IPv4, disk/bandwidth usage, file count and process count.
- Keeps every tool in its prospective functional container.
- Restores strong visual recognition with a same-origin SVG icon system: consistent, recognizable tool glyphs with category-specific color treatments rather than emoji or generic monochrome blocks.

## File Manager recovery

- Replaces the limited write/list workflow with an account-scoped explorer.
- Supports directory navigation and breadcrumbs, file/folder creation, multi-file upload, text editing, download, rename/move, copy, permissions, search, ZIP create/extract, individual delete and multi-select delete.
- Advanced file mutations are certified against the Linux-user adapter. Recursive self-copy and in-source archive destinations fail closed; search/archive/extract work is bounded to prevent runaway control-plane operations.
- Parent traversal and symlink traversal fail closed.
- Browser upload/download limits are bounded; ZIP extraction rejects over-large entries, more than 5,000 entries, or more than 512 MiB declared/actual extraction instead of silently truncating or expanding without limit.

## Metrics and analytics recovery

- Adds first-class Resource Usage, Visitors, Analytics, Bandwidth, Raw Access and Errors pages.
- Usage is account-owned disk/file/process/memory/CPU data.
- Traffic analytics are derived from the account's live managed-domain Nginx access/error logs.
- Shows unique visitors, requests, bandwidth, 4xx/5xx totals, top paths, referrers, status codes, per-day/per-domain traffic, recent access events and recent errors.
- Log reads use bounded tail windows so analytics cannot consume unbounded control-plane time or memory.

## Cumulative safety

6.72 retains the 6.71 PCC Config Editor, curated server Components manager, Laravel stack and Roundcube provisioning; 6.70 database credentials/lifecycle; 6.69 phpMyAdmin; and prior DNS/site/AutoSSL reliability contracts.
