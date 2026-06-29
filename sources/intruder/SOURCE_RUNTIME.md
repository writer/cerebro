# Intruder

Generated Source Runtime SDK scaffold for `intruder`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/intruder`
- Health endpoint: `/source-runtimes/health?source_id=intruder`
- Source health receipt: `sources/intruder/source_health_receipt.json`
- EvidenceCAS reference kind: `intruder.evidence_cas_reference`

## Families

- `assets`, emits `intruder.assets`, reads `/v1/assets`
- `findings`, emits `intruder.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `intruder.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `intruder.policies`, reads `/v1/policies`
- `audit_events`, emits `intruder.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/intruder ./internal/sourceprojection -count=1`
- `make catalog-check`
