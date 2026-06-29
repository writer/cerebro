# nextAuth

Generated Source Runtime SDK scaffold for `n_auth`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/n_auth`
- Health endpoint: `/source-runtimes/health?source_id=n_auth`
- Source health receipt: `sources/n_auth/source_health_receipt.json`
- EvidenceCAS reference kind: `n_auth.evidence_cas_reference`

## Families

- `apikey`, emits `n_auth.apikey`, reads `/apikeys/`
- `account`, emits `n_auth.account`, reads `/servers/${config.serverid}/accounts/`
- `permission`, emits `n_auth.permission`, reads `/servers/${config.serverid}/permissions/`
- `user`, emits `n_auth.user`, reads `/servers/${config.serverid}/users/`

## Tests

- `go test ./sources/n_auth ./internal/sourceprojection -count=1`
- `make catalog-check`
