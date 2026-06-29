# Hadrian Security

Generated Source Runtime SDK scaffold for `hadrian_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hadrian_security`
- Health endpoint: `/source-runtimes/health?source_id=hadrian_security`
- Source health receipt: `sources/hadrian_security/source_health_receipt.json`
- EvidenceCAS reference kind: `hadrian_security.evidence_cas_reference`

## Families

- `assets`, emits `hadrian_security.assets`, reads `/v1/assets`
- `findings`, emits `hadrian_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `hadrian_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `hadrian_security.policies`, reads `/v1/policies`
- `audit_events`, emits `hadrian_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/hadrian_security ./internal/sourceprojection -count=1`
- `make catalog-check`
