# Privora Panel 5.0.0-dev.6.22 — Hosting Environment Auto-Discovery Fresh Core

This development checkpoint changes website onboarding from package-first provisioning to detected-host provisioning.

- Fresh install captures the authoritative live-host inventory as an installation baseline.
- Existing human Linux hosting identities under `/home` are discovered even when they were not created by Privora.
- Existing Nginx document-root ownership continues to enrich account discovery.
- The inventory reports the detected control-panel/web-server environment where safely identifiable.
- Create Website no longer asks for a hosting package.
- A single detected active hosting owner is selected automatically.
- Multiple detected owners remain selectable so Privora does not guess ownership.
- When no eligible hosting identity exists, real-host site creation provisions a dedicated automatic owner without requiring a package choice.
- Discovered accounts are adopted into Privora state before a site mutation, fixing the live-host state-recording gap.
- Manual Create Hosting Account/package provisioning remains available as an advanced administrative workflow.
