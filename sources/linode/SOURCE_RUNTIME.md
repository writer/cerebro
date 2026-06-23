# Linode

Generated Source Runtime SDK scaffold for `linode`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/linode`
- Health endpoint: `/source-runtimes/health?source_id=linode`
- Source health receipt: `sources/linode/source_health_receipt.json`
- EvidenceCAS reference kind: `linode.evidence_cas_reference`

## Families

- `issue`, emits `linode.issue`, reads `/managed/issues`
- `event`, emits `linode.event`, reads `/account/events`
- `credential`, emits `linode.credential`, reads `/managed/credentials`
- `user`, emits `linode.user`, reads `/account/users`

## Tests

- `go test ./sources/linode ./internal/sourceprojection -count=1`
- `make catalog-check`
