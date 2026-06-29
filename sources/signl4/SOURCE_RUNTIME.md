# SIGNL4

Generated Source Runtime SDK scaffold for `signl4`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/signl4`
- Health endpoint: `/source-runtimes/health?source_id=signl4`
- Source health receipt: `sources/signl4/source_health_receipt.json`
- EvidenceCAS reference kind: `signl4.evidence_cas_reference`

## Families

- `team`, emits `signl4.team`, reads `/teams`
- `user`, emits `signl4.user`, reads `/users`
- `membership`, emits `signl4.membership`, reads `/teams/${config.teamid}/memberships`
- `image`, emits `signl4.image`, reads `/categories/images`

## Tests

- `go test ./sources/signl4 ./internal/sourceprojection -count=1`
- `make catalog-check`
