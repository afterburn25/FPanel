# Privora 5.0.0-dev.6.66 — Explicit Nameserver Assignment & Core Status Fail-Soft

- Hosted root domains explicitly map to a nameserver set; domain-name matching never chooses a set implicitly.
- Unassigned domains use the administrator-selected default nameserver set.
- Existing managed BIND zones have apex NS records rewritten during reconciliation when the assignment/default changes.
- Retired in-bailiwick nameserver glue A/AAAA records are removed when switching a zone to an out-of-bailiwick nameserver set.
- PCC Nameserver Manager exposes domain-to-set assignment controls.
- Update Center core-status HTTP failures degrade to the locally known installed version instead of displaying CORE STATUS UNAVAILABLE when package status is still available.
