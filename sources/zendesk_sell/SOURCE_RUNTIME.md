# Zendesk Sell

Generated Source Runtime SDK scaffold for `zendesk_sell`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zendesk_sell`
- Health endpoint: `/source-runtimes/health?source_id=zendesk_sell`
- Source health receipt: `sources/zendesk_sell/source_health_receipt.json`
- EvidenceCAS reference kind: `zendesk_sell.evidence_cas_reference`

## Families

- `users`, emits `zendesk_sell.users`, reads `/v1/users`
- `accounts`, emits `zendesk_sell.accounts`, reads `/v1/accounts`
- `records`, emits `zendesk_sell.records`, reads `/v1/records`
- `policies`, emits `zendesk_sell.policies`, reads `/v1/policies`
- `audit_events`, emits `zendesk_sell.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/zendesk_sell ./internal/sourceprojection -count=1`
- `make catalog-check`
