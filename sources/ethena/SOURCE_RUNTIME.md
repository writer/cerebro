# Ethena

Generated Source Runtime SDK scaffold for `ethena`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/ethena`
- Health endpoint: `/source-runtimes/health?source_id=ethena`
- Source health receipt: `sources/ethena/source_health_receipt.json`
- EvidenceCAS reference kind: `ethena.evidence_cas_reference`

## Families

- `users`, emits `ethena.users`, reads `/v1/users`
- `training_statuses`, emits `ethena.training_statuses`, reads `/v1/training/statuses`
- `course_assignments`, emits `ethena.course_assignments`, reads `/v1/course-assignments`

## Tests

- `go test ./sources/ethena ./internal/sourceprojection -count=1`
- `make catalog-check`
