# Privora Panel 2.0–5.0 architecture boundary — dev.3

The source now contains real durable control-plane primitives for future horizons. These primitives are intentionally separated from production promotion.

## 2.0 Fleet

Implemented locally:
- TLS 1.3 mTLS channel;
- per-node certificate identity checks;
- typed command executor;
- durable nonce replay store;
- persistent enrollment registry with certificate fingerprint/serial/expiry;
- certificate rotation and revocation.

Not yet production: remote node bootstrap, CA custody/rotation distribution, convergence under partitions and real cluster adapters.

## 3.0 Cloud

Implemented locally:
- provider interface;
- durable idempotent lifecycle coordinator;
- fail-closed ambiguous restart state;
- exact destructive-delete confirmation;
- AES-256-GCM provider-secret vault.

Not yet production: real provider API adapters, operational credential rotation, signed node bootstrap, cost/tag reconciliation and provider failure certification.

## 4.0 Automation

Implemented locally:
- restart-durable order journal;
- persisted step progress;
- reverse compensation;
- fail-closed incomplete recovery;
- hash-chained double-entry billing ledger exposed through protected agent routes.

Not yet production: real payment gateways/webhooks, subscription/refund/suspension flows and commercial reconciliation.

## 5.0 Fabric

Implemented locally:
- persistent node/workload/placement controller;
- capacity/region placement and failover replanning;
- majority-observation epoch safety decision;
- fence-and-replace intent;
- healthy-backend route plan.

Not yet production: data replication, deployed distributed consensus, an external fencing authority, live traffic steering, cross-region secret/state distribution and chaos certification.
