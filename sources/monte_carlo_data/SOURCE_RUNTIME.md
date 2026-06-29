# Monte Carlo Data

Generated Source Runtime SDK scaffold for `monte_carlo_data`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/monte_carlo_data`
- Health endpoint: `/source-runtimes/health?source_id=monte_carlo_data`
- Source health receipt: `sources/monte_carlo_data/source_health_receipt.json`
- EvidenceCAS reference kind: `monte_carlo_data.evidence_cas_reference`

## Families

- `users`, emits `monte_carlo_data.users`, reads `/v1/users`
- `accounts`, emits `monte_carlo_data.accounts`, reads `/v1/accounts`
- `records`, emits `monte_carlo_data.records`, reads `/v1/records`
- `policies`, emits `monte_carlo_data.policies`, reads `/v1/policies`
- `audit_events`, emits `monte_carlo_data.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/monte_carlo_data ./internal/sourceprojection -count=1`
- `make catalog-check`
