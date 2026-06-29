# Mparticle

Generated Source Runtime SDK scaffold for `mparticle`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mparticle`
- Health endpoint: `/source-runtimes/health?source_id=mparticle`
- Source health receipt: `sources/mparticle/source_health_receipt.json`
- EvidenceCAS reference kind: `mparticle.evidence_cas_reference`

## Families

- `users`, emits `mparticle.users`, reads `/v1/users`
- `accounts`, emits `mparticle.accounts`, reads `/v1/accounts`
- `records`, emits `mparticle.records`, reads `/v1/records`
- `policies`, emits `mparticle.policies`, reads `/v1/policies`
- `audit_events`, emits `mparticle.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/mparticle ./internal/sourceprojection -count=1`
- `make catalog-check`
