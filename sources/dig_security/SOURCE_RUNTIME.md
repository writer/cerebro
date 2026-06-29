# Dig Security

Generated Source Runtime SDK scaffold for `dig_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/dig_security`
- Health endpoint: `/source-runtimes/health?source_id=dig_security`
- Source health receipt: `sources/dig_security/source_health_receipt.json`
- EvidenceCAS reference kind: `dig_security.evidence_cas_reference`

## Families

- `assets`, emits `dig_security.assets`, reads `/v1/assets`
- `findings`, emits `dig_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `dig_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `dig_security.policies`, reads `/v1/policies`
- `audit_events`, emits `dig_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/dig_security ./internal/sourceprojection -count=1`
- `make catalog-check`
