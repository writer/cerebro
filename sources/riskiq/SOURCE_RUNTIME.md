# Riskiq

Generated Source Runtime SDK scaffold for `riskiq`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/riskiq`
- Health endpoint: `/source-runtimes/health?source_id=riskiq`
- Source health receipt: `sources/riskiq/source_health_receipt.json`
- EvidenceCAS reference kind: `riskiq.evidence_cas_reference`

## Families

- `assets`, emits `riskiq.assets`, reads `/v1/assets`
- `findings`, emits `riskiq.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `riskiq.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `riskiq.policies`, reads `/v1/policies`
- `audit_events`, emits `riskiq.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/riskiq ./internal/sourceprojection -count=1`
- `make catalog-check`
