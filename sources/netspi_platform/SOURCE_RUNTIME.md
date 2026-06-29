# Netspi Platform

Generated Source Runtime SDK scaffold for `netspi_platform`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/netspi_platform`
- Health endpoint: `/source-runtimes/health?source_id=netspi_platform`
- Source health receipt: `sources/netspi_platform/source_health_receipt.json`
- EvidenceCAS reference kind: `netspi_platform.evidence_cas_reference`

## Families

- `assets`, emits `netspi_platform.assets`, reads `/v1/assets`
- `findings`, emits `netspi_platform.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `netspi_platform.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `netspi_platform.policies`, reads `/v1/policies`
- `audit_events`, emits `netspi_platform.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/netspi_platform ./internal/sourceprojection -count=1`
- `make catalog-check`
