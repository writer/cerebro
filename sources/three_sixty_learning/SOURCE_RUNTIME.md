# Three Sixty Learning

Generated Source Runtime SDK scaffold for `three_sixty_learning`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/three_sixty_learning`
- Health endpoint: `/source-runtimes/health?source_id=three_sixty_learning`
- Source health receipt: `sources/three_sixty_learning/source_health_receipt.json`
- EvidenceCAS reference kind: `three_sixty_learning.evidence_cas_reference`

## Families

- `users`, emits `three_sixty_learning.users`, reads `/v1/users`
- `accounts`, emits `three_sixty_learning.accounts`, reads `/v1/accounts`
- `records`, emits `three_sixty_learning.records`, reads `/v1/records`
- `policies`, emits `three_sixty_learning.policies`, reads `/v1/policies`
- `audit_events`, emits `three_sixty_learning.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/three_sixty_learning ./internal/sourceprojection -count=1`
- `make catalog-check`
