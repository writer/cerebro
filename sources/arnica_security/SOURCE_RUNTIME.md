# Arnica Security

Generated Source Runtime SDK scaffold for `arnica_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/arnica_security`
- Health endpoint: `/source-runtimes/health?source_id=arnica_security`
- Source health receipt: `sources/arnica_security/source_health_receipt.json`
- EvidenceCAS reference kind: `arnica_security.evidence_cas_reference`

## Families

- `assets`, emits `arnica_security.assets`, reads `/v1/assets`
- `findings`, emits `arnica_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `arnica_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `arnica_security.policies`, reads `/v1/policies`
- `audit_events`, emits `arnica_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/arnica_security ./internal/sourceprojection -count=1`
- `make catalog-check`
