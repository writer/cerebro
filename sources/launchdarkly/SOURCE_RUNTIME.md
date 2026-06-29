# LaunchDarkly

Generated Source Runtime SDK scaffold for `launchdarkly`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/launchdarkly`
- Health endpoint: `/source-runtimes/health?source_id=launchdarkly`
- Source health receipt: `sources/launchdarkly/source_health_receipt.json`
- EvidenceCAS reference kind: `launchdarkly.evidence_cas_reference`

## Families

- `repositories`, emits `launchdarkly.repositories`, reads `/v1/repositories`
- `users`, emits `launchdarkly.users`, reads `/v1/users`
- `audit_events`, emits `launchdarkly.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/launchdarkly ./internal/sourceprojection -count=1`
- `make catalog-check`
