# Privora Panel 5.0.0-dev.6.29 — BIND Include Syntax Recovery

Fresh-install/live-repair recovery after 6.26 exposed an invalid shell quoting bug in the DNS foundation installer. The generated BIND directive could become `include /etc/bind/privora-zones.conf;`, which `named-checkconf` rejects because the included path must be quoted.

6.27 generates `include "/etc/bind/privora-zones.conf";`, keeps the existing DNS lifecycle/nameserver/site-delete/config-editor work from 6.26, and adds regression coverage for the exact directive.
