# Alchemer

Provider-verified Source Runtime SDK for `alchemer`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `api_token` and `api_token_secret` query parameters
- Default API base URL: regional Alchemer API domain, for example `https://api.alchemer.com`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/alchemer`
- Health endpoint: `/source-runtimes/health?source_id=alchemer`
- Source health receipt: `sources/alchemer/source_health_receipt.json`
- EvidenceCAS reference kind: `alchemer.evidence_cas_reference`

## Families

- `account`, emits `alchemer.account`, reads `GET /v5/account`
- `account_users`, emits `alchemer.account_users`, reads `GET /v5/accountuser`
- `account_teams`, emits `alchemer.account_teams`, reads `GET /v5/accountteams`
- `surveys`, emits `alchemer.surveys`, reads `GET /v5/survey`
- `contact_lists`, emits `alchemer.contact_lists`, reads `GET /v5/contactlist`
- `sso_integrations`, emits `alchemer.sso_integrations`, reads `GET /v5/sso`

## Tests

- `go test ./sources/alchemer ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/alchemer/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
