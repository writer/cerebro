# Netdocuments

Generated Source Runtime SDK scaffold for `netdocuments`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/netdocuments`
- Health endpoint: `/source-runtimes/health?source_id=netdocuments`
- Source health receipt: `sources/netdocuments/source_health_receipt.json`
- EvidenceCAS reference kind: `netdocuments.evidence_cas_reference`

## Families

- `users`, emits `netdocuments.users`, reads `/v1/users`
- `accounts`, emits `netdocuments.accounts`, reads `/v1/accounts`
- `records`, emits `netdocuments.records`, reads `/v1/records`
- `policies`, emits `netdocuments.policies`, reads `/v1/policies`
- `audit_events`, emits `netdocuments.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/netdocuments ./internal/sourceprojection -count=1`
- `make catalog-check`
