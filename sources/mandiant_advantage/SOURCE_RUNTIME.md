# Mandiant Advantage

Generated Source Runtime SDK scaffold for `mandiant_advantage`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mandiant_advantage`
- Health endpoint: `/source-runtimes/health?source_id=mandiant_advantage`
- Source health receipt: `sources/mandiant_advantage/source_health_receipt.json`
- EvidenceCAS reference kind: `mandiant_advantage.evidence_cas_reference`

## Families

- `assets`, emits `mandiant_advantage.assets`, reads `/v1/assets`
- `findings`, emits `mandiant_advantage.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `mandiant_advantage.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `mandiant_advantage.policies`, reads `/v1/policies`
- `audit_events`, emits `mandiant_advantage.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/mandiant_advantage ./internal/sourceprojection -count=1`
- `make catalog-check`
