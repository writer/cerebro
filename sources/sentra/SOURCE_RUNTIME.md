# Sentra

Generated Source Runtime SDK scaffold for `sentra`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sentra`
- Health endpoint: `/source-runtimes/health?source_id=sentra`
- Source health receipt: `sources/sentra/source_health_receipt.json`
- EvidenceCAS reference kind: `sentra.evidence_cas_reference`

## Families

- `assets`, emits `sentra.assets`, reads `/v1/assets`
- `findings`, emits `sentra.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `sentra.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `sentra.policies`, reads `/v1/policies`
- `audit_events`, emits `sentra.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sentra ./internal/sourceprojection -count=1`
- `make catalog-check`
