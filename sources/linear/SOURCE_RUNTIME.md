# Linear

Generated Source Runtime SDK scaffold for `linear`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/linear`
- Health endpoint: `/source-runtimes/health?source_id=linear`
- Source health receipt: `sources/linear/source_health_receipt.json`
- EvidenceCAS reference kind: `linear.evidence_cas_reference`

## Families

- `users`, emits `linear.users`, reads `/v1/users`
- `projects`, emits `linear.projects`, reads `/v1/projects`
- `audit_events`, emits `linear.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/linear ./internal/sourceprojection -count=1`
- `make catalog-check`
