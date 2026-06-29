# Brinqa

Generated Source Runtime SDK scaffold for `brinqa`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/brinqa`
- Health endpoint: `/source-runtimes/health?source_id=brinqa`
- Source health receipt: `sources/brinqa/source_health_receipt.json`
- EvidenceCAS reference kind: `brinqa.evidence_cas_reference`

## Families

- `assets`, emits `brinqa.assets`, reads `/v1/assets`
- `findings`, emits `brinqa.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `brinqa.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `brinqa.policies`, reads `/v1/policies`
- `audit_events`, emits `brinqa.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/brinqa ./internal/sourceprojection -count=1`
- `make catalog-check`
