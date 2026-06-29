# Stackhawk

Generated Source Runtime SDK scaffold for `stackhawk`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/stackhawk`
- Health endpoint: `/source-runtimes/health?source_id=stackhawk`
- Source health receipt: `sources/stackhawk/source_health_receipt.json`
- EvidenceCAS reference kind: `stackhawk.evidence_cas_reference`

## Families

- `assets`, emits `stackhawk.assets`, reads `/v1/assets`
- `findings`, emits `stackhawk.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `stackhawk.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `stackhawk.policies`, reads `/v1/policies`
- `audit_events`, emits `stackhawk.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/stackhawk ./internal/sourceprojection -count=1`
- `make catalog-check`
