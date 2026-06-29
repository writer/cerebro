# Heap

Generated Source Runtime SDK scaffold for `heap`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/heap`
- Health endpoint: `/source-runtimes/health?source_id=heap`
- Source health receipt: `sources/heap/source_health_receipt.json`
- EvidenceCAS reference kind: `heap.evidence_cas_reference`

## Families

- `users`, emits `heap.users`, reads `/v1/users`
- `accounts`, emits `heap.accounts`, reads `/v1/accounts`
- `records`, emits `heap.records`, reads `/v1/records`
- `policies`, emits `heap.policies`, reads `/v1/policies`
- `audit_events`, emits `heap.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/heap ./internal/sourceprojection -count=1`
- `make catalog-check`
