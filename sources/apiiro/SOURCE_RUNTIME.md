# Apiiro

Generated Source Runtime SDK scaffold for `apiiro`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/apiiro`
- Health endpoint: `/source-runtimes/health?source_id=apiiro`
- Source health receipt: `sources/apiiro/source_health_receipt.json`
- EvidenceCAS reference kind: `apiiro.evidence_cas_reference`

## Families

- `assets`, emits `apiiro.assets`, reads `/v1/assets`
- `findings`, emits `apiiro.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `apiiro.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `apiiro.policies`, reads `/v1/policies`
- `audit_events`, emits `apiiro.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/apiiro ./internal/sourceprojection -count=1`
- `make catalog-check`
