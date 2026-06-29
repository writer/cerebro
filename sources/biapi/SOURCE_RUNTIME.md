# Powens (Budgea)

Generated Source Runtime SDK scaffold for `biapi`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/biapi`
- Health endpoint: `/source-runtimes/health?source_id=biapi`
- Source health receipt: `sources/biapi/source_health_receipt.json`
- EvidenceCAS reference kind: `biapi.evidence_cas_reference`

## Families

- `logo`, emits `biapi.logo`, reads `/banks/${config.id_connector}/logos`
- `account`, emits `biapi.account`, reads `/users/${config.id_user}/connections/${config.id_connection}/accounts`
- `add_to_data`, emits `biapi.add_to_data`, reads `/webhooks/${config.id_webhook}/add_to_data`
- `alert`, emits `biapi.alert`, reads `/users/${config.id_user}/alerts`

## Tests

- `go test ./sources/biapi ./internal/sourceprojection -count=1`
- `make catalog-check`
