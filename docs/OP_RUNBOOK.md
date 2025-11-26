# Operations Runbook — Infinite AI Security

## Incident Severity
- SEV0: Data loss / major outage
- SEV1: Degraded core functions
- SEV2: Minor impact

## On-call
- Contact: oncall@company.local
- Escalation: PagerDuty -> SRE lead -> CISO

## Standard Playbooks
- Auth outage: rotate signing keys, failover OIDC, enable maintenance banner
- DB incident: promote replica, set `read_only`, initiate PITR
- Anchor backlog: pause batching, increase relayer pods, monitor gas

## Logs & Audit
- All admin actions logged to `ai_hub.audit_log` and anchored in batches
- Retention: hot 30d, warm 180d, cold WORM 1y

## DR
- RTO: 30m, RPO: 5m
- Quarterly DR drills with checklist
