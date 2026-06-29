# Huntr

Generated Source Runtime SDK scaffold for `huntr`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/huntr`
- Health endpoint: `/source-runtimes/health?source_id=huntr`
- Source health receipt: `sources/huntr/source_health_receipt.json`
- EvidenceCAS reference kind: `huntr.evidence_cas_reference`

## Families

- `assets`, emits `huntr.assets`, reads `/v1/assets`
- `findings`, emits `huntr.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `huntr.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `huntr.policies`, reads `/v1/policies`
- `audit_events`, emits `huntr.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/huntr ./internal/sourceprojection -count=1`
- `make catalog-check`
