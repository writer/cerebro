# Zscaler Internet Access

Generated Source Runtime SDK scaffold for `zscaler_internet_access`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/zscaler_internet_access`
- Health endpoint: `/source-runtimes/health?source_id=zscaler_internet_access`
- Source health receipt: `sources/zscaler_internet_access/source_health_receipt.json`
- EvidenceCAS reference kind: `zscaler_internet_access.evidence_cas_reference`

## Families

- `users`, emits `zscaler_internet_access.users`, reads `/v1/users`
- `groups`, emits `zscaler_internet_access.groups`, reads `/v1/groups`
- `roles`, emits `zscaler_internet_access.roles`, reads `/v1/roles`
- `applications`, emits `zscaler_internet_access.applications`, reads `/v1/applications`
- `audit_events`, emits `zscaler_internet_access.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/zscaler_internet_access ./internal/sourceprojection -count=1`
- `make catalog-check`
