# Material Security

Generated Source Runtime SDK scaffold for `material_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/material_security`
- Health endpoint: `/source-runtimes/health?source_id=material_security`
- Source health receipt: `sources/material_security/source_health_receipt.json`
- EvidenceCAS reference kind: `material_security.evidence_cas_reference`

## Families

- `assets`, emits `material_security.assets`, reads `/v1/assets`
- `findings`, emits `material_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `material_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `material_security.policies`, reads `/v1/policies`
- `audit_events`, emits `material_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/material_security ./internal/sourceprojection -count=1`
- `make catalog-check`
