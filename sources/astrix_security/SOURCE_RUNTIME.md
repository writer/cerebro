# Astrix Security

Generated Source Runtime SDK scaffold for `astrix_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/astrix_security`
- Health endpoint: `/source-runtimes/health?source_id=astrix_security`
- Source health receipt: `sources/astrix_security/source_health_receipt.json`
- EvidenceCAS reference kind: `astrix_security.evidence_cas_reference`

## Families

- `assets`, emits `astrix_security.assets`, reads `/v1/assets`
- `findings`, emits `astrix_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `astrix_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `astrix_security.policies`, reads `/v1/policies`
- `audit_events`, emits `astrix_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/astrix_security ./internal/sourceprojection -count=1`
- `make catalog-check`
