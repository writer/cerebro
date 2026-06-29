# Churnzero

Generated Source Runtime SDK scaffold for `churnzero`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/churnzero`
- Health endpoint: `/source-runtimes/health?source_id=churnzero`
- Source health receipt: `sources/churnzero/source_health_receipt.json`
- EvidenceCAS reference kind: `churnzero.evidence_cas_reference`

## Families

- `users`, emits `churnzero.users`, reads `/v1/users`
- `accounts`, emits `churnzero.accounts`, reads `/v1/accounts`
- `records`, emits `churnzero.records`, reads `/v1/records`
- `policies`, emits `churnzero.policies`, reads `/v1/policies`
- `audit_events`, emits `churnzero.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/churnzero ./internal/sourceprojection -count=1`
- `make catalog-check`
