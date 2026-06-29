# Securityscorecard

Generated Source Runtime SDK scaffold for `securityscorecard`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/securityscorecard`
- Health endpoint: `/source-runtimes/health?source_id=securityscorecard`
- Source health receipt: `sources/securityscorecard/source_health_receipt.json`
- EvidenceCAS reference kind: `securityscorecard.evidence_cas_reference`

## Families

- `assets`, emits `securityscorecard.assets`, reads `/v1/assets`
- `findings`, emits `securityscorecard.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `securityscorecard.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `securityscorecard.policies`, reads `/v1/policies`
- `audit_events`, emits `securityscorecard.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/securityscorecard ./internal/sourceprojection -count=1`
- `make catalog-check`
