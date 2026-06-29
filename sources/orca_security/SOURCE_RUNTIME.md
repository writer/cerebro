# Orca Security

Generated Source Runtime SDK scaffold for `orca_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/orca_security`
- Health endpoint: `/source-runtimes/health?source_id=orca_security`
- Source health receipt: `sources/orca_security/source_health_receipt.json`
- EvidenceCAS reference kind: `orca_security.evidence_cas_reference`

## Families

- `assets`, emits `orca_security.assets`, reads `/v1/assets`
- `findings`, emits `orca_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `orca_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `orca_security.policies`, reads `/v1/policies`
- `audit_events`, emits `orca_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/orca_security ./internal/sourceprojection -count=1`
- `make catalog-check`
