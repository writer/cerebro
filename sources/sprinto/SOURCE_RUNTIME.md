# Sprinto

Generated Source Runtime SDK scaffold for `sprinto`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sprinto`
- Health endpoint: `/source-runtimes/health?source_id=sprinto`
- Source health receipt: `sources/sprinto/source_health_receipt.json`
- EvidenceCAS reference kind: `sprinto.evidence_cas_reference`

## Families

- `assets`, emits `sprinto.assets`, reads `/v1/assets`
- `findings`, emits `sprinto.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `sprinto.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `sprinto.policies`, reads `/v1/policies`
- `audit_events`, emits `sprinto.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sprinto ./internal/sourceprojection -count=1`
- `make catalog-check`
