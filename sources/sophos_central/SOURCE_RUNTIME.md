# Sophos Central

Generated Source Runtime SDK scaffold for `sophos_central`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sophos_central`
- Health endpoint: `/source-runtimes/health?source_id=sophos_central`
- Source health receipt: `sources/sophos_central/source_health_receipt.json`
- EvidenceCAS reference kind: `sophos_central.evidence_cas_reference`

## Families

- `assets`, emits `sophos_central.assets`, reads `/v1/assets`
- `findings`, emits `sophos_central.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `sophos_central.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `sophos_central.policies`, reads `/v1/policies`
- `audit_events`, emits `sophos_central.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sophos_central ./internal/sourceprojection -count=1`
- `make catalog-check`
