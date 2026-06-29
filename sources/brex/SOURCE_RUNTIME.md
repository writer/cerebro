# Brex

Generated Source Runtime SDK scaffold for `brex`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/brex`
- Health endpoint: `/source-runtimes/health?source_id=brex`
- Source health receipt: `sources/brex/source_health_receipt.json`
- EvidenceCAS reference kind: `brex.evidence_cas_reference`

## Families

- `cards`, emits `brex.cards`, reads `/v2/cards`
- `users`, emits `brex.users`, reads `/v2/users`
- `audit_events`, emits `brex.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/brex ./internal/sourceprojection -count=1`
- `make catalog-check`
