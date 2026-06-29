# Abnormal Security

Generated Source Runtime SDK scaffold for `abnormal_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/abnormal_security`
- Health endpoint: `/source-runtimes/health?source_id=abnormal_security`
- Source health receipt: `sources/abnormal_security/source_health_receipt.json`
- EvidenceCAS reference kind: `abnormal_security.evidence_cas_reference`

## Families

- `assets`, emits `abnormal_security.assets`, reads `/v1/assets`
- `findings`, emits `abnormal_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `abnormal_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `abnormal_security.policies`, reads `/v1/policies`
- `audit_events`, emits `abnormal_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/abnormal_security ./internal/sourceprojection -count=1`
- `make catalog-check`
