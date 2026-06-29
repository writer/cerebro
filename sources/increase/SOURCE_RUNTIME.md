# Increase

Generated Source Runtime SDK scaffold for `increase`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/increase`
- Health endpoint: `/source-runtimes/health?source_id=increase`
- Source health receipt: `sources/increase/source_health_receipt.json`
- EvidenceCAS reference kind: `increase.evidence_cas_reference`

## Families

- `event`, emits `increase.event`, reads `/events`
- `account`, emits `increase.account`, reads `/accounts`
- `digital_wallet_token`, emits `increase.digital_wallet_token`, reads `/digital_wallet_tokens`
- `ach_prenotification`, emits `increase.ach_prenotification`, reads `/ach_prenotifications`
- `oauth_connection`, emits `increase.oauth_connection`, reads `/oauth_connections`
- `event_subscription`, emits `increase.event_subscription`, reads `/event_subscriptions`
- `account_number`, emits `increase.account_number`, reads `/account_numbers`
- `account_statement`, emits `increase.account_statement`, reads `/account_statements`
- `account_transfer`, emits `increase.account_transfer`, reads `/account_transfers`
- `external_account`, emits `increase.external_account`, reads `/external_accounts`
- `ach_transfer`, emits `increase.ach_transfer`, reads `/ach_transfers`
- `card`, emits `increase.card`, reads `/cards`

## Tests

- `go test ./sources/increase ./internal/sourceprojection -count=1`
- `make catalog-check`
