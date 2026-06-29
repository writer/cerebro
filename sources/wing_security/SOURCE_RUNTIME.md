# Wing Security

Generated Source Runtime SDK scaffold for `wing_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/wing_security`
- Health endpoint: `/source-runtimes/health?source_id=wing_security`
- Source health receipt: `sources/wing_security/source_health_receipt.json`
- EvidenceCAS reference kind: `wing_security.evidence_cas_reference`

## Families

- `assets`, emits `wing_security.assets`, reads `/v1/assets`
- `findings`, emits `wing_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `wing_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `wing_security.policies`, reads `/v1/policies`
- `audit_events`, emits `wing_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/wing_security ./internal/sourceprojection -count=1`
- `make catalog-check`
