# Bigid

Generated Source Runtime SDK scaffold for `bigid`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bigid`
- Health endpoint: `/source-runtimes/health?source_id=bigid`
- Source health receipt: `sources/bigid/source_health_receipt.json`
- EvidenceCAS reference kind: `bigid.evidence_cas_reference`

## Families

- `assets`, emits `bigid.assets`, reads `/v1/assets`
- `findings`, emits `bigid.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `bigid.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `bigid.policies`, reads `/v1/policies`
- `audit_events`, emits `bigid.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/bigid ./internal/sourceprojection -count=1`
- `make catalog-check`
