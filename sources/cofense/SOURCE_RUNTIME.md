# Cofense

Generated Source Runtime SDK scaffold for `cofense`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cofense`
- Health endpoint: `/source-runtimes/health?source_id=cofense`
- Source health receipt: `sources/cofense/source_health_receipt.json`
- EvidenceCAS reference kind: `cofense.evidence_cas_reference`

## Families

- `assets`, emits `cofense.assets`, reads `/v1/assets`
- `findings`, emits `cofense.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `cofense.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `cofense.policies`, reads `/v1/policies`
- `audit_events`, emits `cofense.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cofense ./internal/sourceprojection -count=1`
- `make catalog-check`
