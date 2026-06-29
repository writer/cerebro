# Claroty

Generated Source Runtime SDK scaffold for `claroty`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/claroty`
- Health endpoint: `/source-runtimes/health?source_id=claroty`
- Source health receipt: `sources/claroty/source_health_receipt.json`
- EvidenceCAS reference kind: `claroty.evidence_cas_reference`

## Families

- `assets`, emits `claroty.assets`, reads `/v1/assets`
- `findings`, emits `claroty.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `claroty.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `claroty.policies`, reads `/v1/policies`
- `audit_events`, emits `claroty.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/claroty ./internal/sourceprojection -count=1`
- `make catalog-check`
