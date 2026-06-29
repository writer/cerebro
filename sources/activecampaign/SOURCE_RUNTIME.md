# Activecampaign

Generated Source Runtime SDK scaffold for `activecampaign`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/activecampaign`
- Health endpoint: `/source-runtimes/health?source_id=activecampaign`
- Source health receipt: `sources/activecampaign/source_health_receipt.json`
- EvidenceCAS reference kind: `activecampaign.evidence_cas_reference`

## Families

- `users`, emits `activecampaign.users`, reads `/v1/users`
- `accounts`, emits `activecampaign.accounts`, reads `/v1/accounts`
- `records`, emits `activecampaign.records`, reads `/v1/records`
- `policies`, emits `activecampaign.policies`, reads `/v1/policies`
- `audit_events`, emits `activecampaign.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/activecampaign ./internal/sourceprojection -count=1`
- `make catalog-check`
