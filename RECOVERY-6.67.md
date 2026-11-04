# Privora 5.0.0-dev.6.67 — Package Deadline, State-Write & Direct DNS Repair

Live 6.66 evidence showed three reliability defects:
- package-manager descendants could keep response pipes open beyond the intended Go context deadline;
- simultaneous panel bootstrap requests used the same panel-state temporary filename and could race during rename;
- the DNS table row action labelled Create zone only selected/scrolled to a second form.

6.67 uses an 8-second package probe budget, kills the complete package-manager process group on timeout, uses unique panel-state temp files, avoids needless package-default writes, and makes row-level Create zone call dns-create directly.
