# Stream

Generated Source Runtime SDK scaffold for `stream_io_api`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/stream_io_api`
- Health endpoint: `/source-runtimes/health?source_id=stream_io_api`
- Source health receipt: `sources/stream_io_api/source_health_receipt.json`
- EvidenceCAS reference kind: `stream_io_api.evidence_cas_reference`

## Families

- `member`, emits `stream_io_api.member`, reads `/members`
- `role`, emits `stream_io_api.role`, reads `/roles`
- `device`, emits `stream_io_api.device`, reads `/devices`
- `query_banned_user`, emits `stream_io_api.query_banned_user`, reads `/query_banned_users`

## Tests

- `go test ./sources/stream_io_api ./internal/sourceprojection -count=1`
- `make catalog-check`
