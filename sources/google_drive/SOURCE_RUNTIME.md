# Google Drive

Generated Source Runtime SDK scaffold for `google_drive`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/google_drive`
- Health endpoint: `/source-runtimes/health?source_id=google_drive`
- Source health receipt: `sources/google_drive/source_health_receipt.json`
- EvidenceCAS reference kind: `google_drive.evidence_cas_reference`

## Families

- `files`, emits `google_drive.files`, reads `/files`
- `shared_drives`, emits `google_drive.shared_drives`, reads `/drives`
- `changes`, emits `google_drive.changes`, reads `/changes`

## Tests

- `go test ./sources/google_drive ./internal/sourceprojection -count=1`
- `make catalog-check`
