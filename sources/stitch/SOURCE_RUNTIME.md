# Stitch

Generated Source Runtime SDK scaffold for `stitch`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/stitch`
- Health endpoint: `/source-runtimes/health?source_id=stitch`
- Source health receipt: `sources/stitch/source_health_receipt.json`
- EvidenceCAS reference kind: `stitch.evidence_cas_reference`

## Families

- `users`, emits `stitch.users`, reads `/v1/users`
- `accounts`, emits `stitch.accounts`, reads `/v1/accounts`
- `records`, emits `stitch.records`, reads `/v1/records`
- `policies`, emits `stitch.policies`, reads `/v1/policies`
- `audit_events`, emits `stitch.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/stitch ./internal/sourceprojection -count=1`
- `make catalog-check`
