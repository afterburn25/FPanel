# Privora control-surface identity

Privora's two control surfaces have official, independent names:

- **Privora Command Center (PCC)** — server, root, reseller and administrative control. Default direct listener: `https://domain:8443`. Convenience entry point: `https://domain/pcc`.
- **Privora Panel (PPanel)** — hosting-account control. Default direct listener: `https://domain:2443`. Convenience entry point: `https://domain/ppanel`.

The convenience paths redirect to the dedicated listener rather than mounting the control application inside a hosted site's PHP runtime. This preserves separate session cookies, role admission rules, recovery behavior and network/firewall boundaries.

PCC contains an **Open Privora Panel (PPanel)** action. Listener ports remain configurable; the convenience aliases are regenerated from the configured values.

The overall server software may be described generically as **Privora** or the **Privora Control Suite**. The old WHM/cPanel-style names are not Privora product-surface names. References to cPanel may still appear only where Privora is explicitly identifying a third-party migration/import source.
