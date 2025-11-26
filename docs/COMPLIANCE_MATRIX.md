# Compliance Matrix (SOC2 / ISO27001 / GDPR) — Infinite AI Security

| Kategori | Kontrol | SOC2 | ISO27001 | GDPR | Implementasi | Status |
|---|---|---|---|---|---|---|
| Access Control | RBAC, SSO/OIDC, short-lived creds | CC6 | A.9 | Art. 32 | Vault, OIDC, RBAC | ✅ |
| AuthN/AuthZ | MFA untuk admin, JWT TTL pendek | CC6 | A.9.4 | Art. 25 | MFA, short TTL | ✅ |
| Secrets Mgmt | Vault Transit + Auto-unseal via HSM | CC6 | A.10 | Art. 32 | Vault + HSM | ⚠️ |
| Encryption | TLS 1.2+, AES-256 at-rest | CC6 | A.10 | Art. 32 | mTLS, KMS/HSM | ✅ |
| Audit Logging | Immutable log + on-chain anchor | CC7 | A.12.4 | Art. 30 | audit_log + anchor | ⚠️ |
| Data Residency | Regional isolation | CC9 | A.18 | Art. 44 | multi-region | ⚠️ |
| Backup/Restore | Encrypted backups + drills | CC7 | A.12.3 | Art. 32 | Backup tested | ⚠️ |
| Incident Response | Runbook, SLA, playbooks | CC7 | A.16 | Art. 33 | OP_RUNBOOK.md | ⚠️ |

Catatan:
- ⚠️ berarti sebagian sudah ada, perlu penyempurnaan. Update setiap rilis.
