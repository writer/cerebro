# Nucleus Security

Generated Source Runtime SDK scaffold for `nucleus_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/nucleus_security`
- Health endpoint: `/source-runtimes/health?source_id=nucleus_security`
- Source health receipt: `sources/nucleus_security/source_health_receipt.json`
- EvidenceCAS reference kind: `nucleus_security.evidence_cas_reference`

## Families

- `assets`, emits `nucleus_security.assets`, reads `/v1/assets`
- `findings`, emits `nucleus_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `nucleus_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `nucleus_security.policies`, reads `/v1/policies`
- `audit_events`, emits `nucleus_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/nucleus_security ./internal/sourceprojection -count=1`
- `make catalog-check`
