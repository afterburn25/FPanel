# Certification Evidence

`sandbox-full-stack-certification.json` is the final full-role certification attempt from the disposable Debian development host. It is **machine-bound, non-portable, and intentionally has status FAIL** because this sandbox could not install the complete hosting stack after its package-manager DNS stopped resolving Debian mirrors.

The evidence is valuable because the Privora full-role gate refused to promote a partial machine and enumerated every missing required adapter. It also records the adapters that did certify in this environment.

This repository evidence is never loaded automatically by the agent. A real VPS must generate its own certification at the configured runtime certification path, and the machine fingerprint must match that VPS.

Evidence SHA-256: `027524401f65ed9c9d4dff7f8133b7a30b3ff1c54f25f7bfb5b992bbca293dd3`.
