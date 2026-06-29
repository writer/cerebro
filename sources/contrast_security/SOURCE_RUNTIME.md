# Contrast Security

Generated Source Runtime SDK scaffold for `contrast_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/contrast_security`
- Health endpoint: `/source-runtimes/health?source_id=contrast_security`
- Source health receipt: `sources/contrast_security/source_health_receipt.json`
- EvidenceCAS reference kind: `contrast_security.evidence_cas_reference`

## Families

- `assets`, emits `contrast_security.assets`, reads `/v1/assets`
- `findings`, emits `contrast_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `contrast_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `contrast_security.policies`, reads `/v1/policies`
- `audit_events`, emits `contrast_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/contrast_security ./internal/sourceprojection -count=1`
- `make catalog-check`
