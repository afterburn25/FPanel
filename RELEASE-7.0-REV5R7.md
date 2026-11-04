# Privora Panel 5.0.0-dev.7.0 Rev5 Rev7 — Manual Mail TLS Routing Repair

- Routes manual certificate issuance for Privora-managed `mail.<domain>` challenge hosts through `InstallLetsEncryptMailTLS` instead of the PHP website TLS installer.
- Preserves `InstallLetsEncryptNginxTLS` and its strict username/PHP validation for normal hosted websites.
- Uses the existing 180-second `AgentClient::postLong` transport for PCC/PPanel manual certificate issuance so Certbot is not constrained by the generic 5-second POST timeout.
- Does not weaken certificate-domain validation, Privora mail-host detection, Agent hardening, or host mutation controls.
- Existing successfully issued certificates are reused; this repair does not require revocation or forced reissuance.
