# Oracle HCM

Generated Source Runtime SDK scaffold for `oracle_hcm`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/oracle_hcm`
- Health endpoint: `/source-runtimes/health?source_id=oracle_hcm`
- Source health receipt: `sources/oracle_hcm/source_health_receipt.json`
- EvidenceCAS reference kind: `oracle_hcm.evidence_cas_reference`

## Families

- `users`, emits `oracle_hcm.users`, reads `/v1/users`
- `accounts`, emits `oracle_hcm.accounts`, reads `/v1/accounts`
- `records`, emits `oracle_hcm.records`, reads `/v1/records`
- `policies`, emits `oracle_hcm.policies`, reads `/v1/policies`
- `audit_events`, emits `oracle_hcm.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/oracle_hcm ./internal/sourceprojection -count=1`
- `make catalog-check`
