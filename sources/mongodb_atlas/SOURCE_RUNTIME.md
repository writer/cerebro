# MongoDB Atlas

Generated Source Runtime SDK scaffold for `mongodb_atlas`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mongodb_atlas`
- Health endpoint: `/source-runtimes/health?source_id=mongodb_atlas`
- Source health receipt: `sources/mongodb_atlas/source_health_receipt.json`
- EvidenceCAS reference kind: `mongodb_atlas.evidence_cas_reference`

## Families

- `assets`, emits `mongodb_atlas.assets`, reads `/v1/assets`
- `audit_events`, emits `mongodb_atlas.audit_events`, reads `/v1/audit/events`
- `vulnerabilities`, emits `mongodb_atlas.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/mongodb_atlas ./internal/sourceprojection -count=1`
- `make catalog-check`
