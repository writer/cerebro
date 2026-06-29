# Buildkite

Generated Source Runtime SDK scaffold for `buildkite`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/buildkite`
- Health endpoint: `/source-runtimes/health?source_id=buildkite`
- Source health receipt: `sources/buildkite/source_health_receipt.json`
- EvidenceCAS reference kind: `buildkite.evidence_cas_reference`

## Families

- `pipelines`, emits `buildkite.pipelines`, reads `/v1/pipelines`
- `findings`, emits `buildkite.findings`, reads `/v1/findings`
- `audit_events`, emits `buildkite.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/buildkite ./internal/sourceprojection -count=1`
- `make catalog-check`
