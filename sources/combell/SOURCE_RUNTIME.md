# Combell

Generated Source Runtime SDK scaffold for `combell`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/combell`
- Health endpoint: `/source-runtimes/health?source_id=combell`
- Source health receipt: `sources/combell/source_health_receipt.json`
- EvidenceCAS reference kind: `combell.evidence_cas_reference`

## Families

- `account`, emits `combell.account`, reads `/accounts`
- `ssh`, emits `combell.ssh`, reads `/ssh`
- `user`, emits `combell.user`, reads `/mysqldatabases/${config.databasename}/users`
- `account_2`, emits `combell.account_2`, reads `/accounts/${config.accountid}`

## Tests

- `go test ./sources/combell ./internal/sourceprojection -count=1`
- `make catalog-check`
