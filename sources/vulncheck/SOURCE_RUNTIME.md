# Vulncheck

Generated Source Runtime SDK scaffold for `vulncheck`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/vulncheck`
- Health endpoint: `/source-runtimes/health?source_id=vulncheck`
- Source health receipt: `sources/vulncheck/source_health_receipt.json`
- EvidenceCAS reference kind: `vulncheck.evidence_cas_reference`

## Families

- `assets`, emits `vulncheck.assets`, reads `/v1/assets`
- `findings`, emits `vulncheck.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `vulncheck.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `vulncheck.policies`, reads `/v1/policies`
- `audit_events`, emits `vulncheck.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/vulncheck ./internal/sourceprojection -count=1`
- `make catalog-check`
