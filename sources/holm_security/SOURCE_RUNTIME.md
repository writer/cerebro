# Holm Security

Generated Source Runtime SDK scaffold for `holm_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/holm_security`
- Health endpoint: `/source-runtimes/health?source_id=holm_security`
- Source health receipt: `sources/holm_security/source_health_receipt.json`
- EvidenceCAS reference kind: `holm_security.evidence_cas_reference`

## Families

- `assets`, emits `holm_security.assets`, reads `/v1/assets`
- `findings`, emits `holm_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `holm_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `holm_security.policies`, reads `/v1/policies`
- `audit_events`, emits `holm_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/holm_security ./internal/sourceprojection -count=1`
- `make catalog-check`
