# Privora 5.0.0-dev.6.60 — Update Center resilience and trust transition

- Update Center OS-package inventory and core-update status refresh independently; one HTTP 500 no longer takes down the whole page.
- Error source/details remain visible while upload/install controls stay usable.
- Carries PCC/PPanel, DNS/BIND reconciliation, website status, AutoSSL/certificate inventory, nameserver/registrar and updater safety fixes from the 6.57 development line.
- Uses the post-loss release trust key introduced by the one-time 6.51 trust bootstrap.
