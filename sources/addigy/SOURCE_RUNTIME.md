# Addigy

Promoted Source Runtime adapter for Addigy API v2.

## Runtime input

- Source type: `addigy_api_v2`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/addigy`
- Health endpoint: `/source-runtimes/health?source_id=addigy`
- Source health receipt: `sources/addigy/source_health_receipt.json`
- EvidenceCAS reference kind: `addigy.evidence_cas_reference`

## Families

- `devices`, emits `addigy.devices`, reads `POST /devices`
- `users`, emits `addigy.users`, reads `POST /o/{organization_id}/users/query`
- `groups`, emits `addigy.groups`, reads `POST /o/{organization_id}/end-users/groups/query`
- `policies`, emits `addigy.policies`, reads `POST /oa/policies/query`
- `audit_events`, emits `addigy.audit_events`, reads `POST /system-events/search`

## Tests

- `go test ./sources/internal/jsonapi ./sources/addigy ./internal/sourceprojection -count=1`
- `make lint-sources catalog-check sourcegen-check`
- `make check-structural check-structural-test check-arch`
- `make connector-catalog-review connector-api-discovery`
