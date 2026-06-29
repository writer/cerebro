# Mastodon

Generated Source Runtime SDK scaffold for `mastodon`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mastodon`
- Health endpoint: `/source-runtimes/health?source_id=mastodon`
- Source health receipt: `sources/mastodon/source_health_receipt.json`
- EvidenceCAS reference kind: `mastodon.evidence_cas_reference`

## Families

- `account`, emits `mastodon.account`, reads `/api/v1/lists/${config.id}/accounts`
- `activity`, emits `mastodon.activity`, reads `/api/v1/instance/activity`
- `verify_credential`, emits `mastodon.verify_credential`, reads `/api/v1/accounts/verify_credentials`
- `notification`, emits `mastodon.notification`, reads `/api/v1/notifications`

## Tests

- `go test ./sources/mastodon ./internal/sourceprojection -count=1`
- `make catalog-check`
