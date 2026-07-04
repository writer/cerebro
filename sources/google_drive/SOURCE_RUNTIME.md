# Google Drive

Runtime coverage for Google Drive file metadata, shared-drive metadata, and Drive change replay.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Runtime families: `files`, `shared_drives`
- Fixture families: `files`, `shared_drives`, `changes`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/google_drive`
- Health endpoint: `/source-runtimes/health?source_id=google_drive`
- Source health receipt: `sources/google_drive/source_health_receipt.json`
- File and shared-drive URNs are synthesized from provider IDs.

## Families

- `files`, emits `google_drive.files`, reads `/files`
- `shared_drives`, emits `google_drive.shared_drives`, reads `/drives`
- `changes`, emits `google_drive.changes`, reads `/changes` when a provider page token is supplied.

## Tests

- `go test ./sources/google_drive ./internal/connectorcatalog ./internal/sourceprojection -count=1`
- `make catalog-check`
