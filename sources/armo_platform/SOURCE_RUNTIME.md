# Armo Platform

Generated Source Runtime SDK scaffold for `armo_platform`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/armo_platform`
- Health endpoint: `/source-runtimes/health?source_id=armo_platform`
- Source health receipt: `sources/armo_platform/source_health_receipt.json`
- EvidenceCAS reference kind: `armo_platform.evidence_cas_reference`

## Families

- `assets`, emits `armo_platform.assets`, reads `/v1/assets`
- `findings`, emits `armo_platform.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `armo_platform.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `armo_platform.policies`, reads `/v1/policies`
- `audit_events`, emits `armo_platform.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/armo_platform ./internal/sourceprojection -count=1`
- `make catalog-check`
