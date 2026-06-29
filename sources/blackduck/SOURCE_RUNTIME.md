# Blackduck

Generated Source Runtime SDK scaffold for `blackduck`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/blackduck`
- Health endpoint: `/source-runtimes/health?source_id=blackduck`
- Source health receipt: `sources/blackduck/source_health_receipt.json`
- EvidenceCAS reference kind: `blackduck.evidence_cas_reference`

## Families

- `assets`, emits `blackduck.assets`, reads `/v1/assets`
- `findings`, emits `blackduck.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `blackduck.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `blackduck.policies`, reads `/v1/policies`
- `audit_events`, emits `blackduck.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/blackduck ./internal/sourceprojection -count=1`
- `make catalog-check`
