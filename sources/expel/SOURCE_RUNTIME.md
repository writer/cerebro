# Expel

Generated Source Runtime SDK scaffold for `expel`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/expel`
- Health endpoint: `/source-runtimes/health?source_id=expel`
- Source health receipt: `sources/expel/source_health_receipt.json`
- EvidenceCAS reference kind: `expel.evidence_cas_reference`

## Families

- `assets`, emits `expel.assets`, reads `/v1/assets`
- `findings`, emits `expel.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `expel.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `expel.policies`, reads `/v1/policies`
- `audit_events`, emits `expel.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/expel ./internal/sourceprojection -count=1`
- `make catalog-check`
