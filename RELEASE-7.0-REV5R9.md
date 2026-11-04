# Privora Panel 5.0.0-dev.7.0 Rev5 Rev9

## Secure Mail Postfix Validation Isolation Repair

Rev5 Rev9 fixes the remaining secure-mail render path that executed `postfix check` directly inside the hardened Privora Agent. `postfix check` invokes `postsuper`, which requires Postfix-owned UID transitions that are intentionally blocked by the Agent's `NoNewPrivileges=true` and `RestrictSUIDSGID=true` hardening.

The secure-mail renderer now reuses the certified `validatePostfixCheck()` helper, which delegates live validation to Privora's narrowly scoped transient root maintenance unit. Certification mode remains hermetic and continues using the injected runner.

Agent hardening is unchanged.
