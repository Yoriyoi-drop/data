# Vault HA + HSM Replication Guide

## Goals
- Highly available Vault in Raft mode, auto-unseal with HSM or Cloud KMS.
- Replication across regions (performance + DR secondary).

## Topology
- Per-region Vault Raft cluster (3+ nodes), internal-only service.
- Auto-unseal via: Cloud KMS (AWS KMS / GCP KMS / Azure Key Vault) or on-prem HSM.
- DR: periodic snapshots replicated to secondary object storage.

## Steps
1. Provision HSM/KMS and create key for auto-unseal.
2. Deploy Vault with Raft storage (`deployment/k8s/vault-ha.yaml` as baseline).
3. Configure auto-unseal in `VAULT_LOCAL_CONFIG` (remove `tls_disable` in prod; use TLS).
4. Initialize Vault once; capture unseal keys if using Shamir; prefer auto-unseal.
5. Enable Transit engine and create `anchor-key`.
6. Enable replication: set primary; join secondary cluster(s).

## Security
- TLS everywhere; use SPIFFE or mTLS between services.
- Restrict `root` token; create tightly scoped policies and roles.
- Audit device enabled; ship logs to WORM storage.

## Policies (example snippets)
```hcl
path "transit/sign/anchor-key" {
  capabilities = ["update"]
}

path "transit/verify/anchor-key" {
  capabilities = ["update"]
}
```

## References
- HashiCorp Vault Reference Architecture
- Auto-unseal with HSM/KMS docs
- Raft Integrated Storage guidance
