# Privora Panel 5.0.0-dev.6.42 Recovery Notes

6.40 is a forward-only core release from the verified 6.39 line. It adds multiple nameserver sets, vertical website inventory, suspended-account deletion, and first-class subdomain lifecycle management.

If an update transaction fails before promotion, leave the live core in place and use Update Center failure provenance. If promotion has occurred, rely on the atomic exchange rollback path. Do not manually delete `/opt/privora-panel` or `/opt/privora-panel.releases`.
