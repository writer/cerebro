# Salesloft

Generated Source Runtime SDK scaffold for `salesloft`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/salesloft`
- Health endpoint: `/source-runtimes/health?source_id=salesloft`
- Source health receipt: `sources/salesloft/source_health_receipt.json`
- EvidenceCAS reference kind: `salesloft.evidence_cas_reference`

## Families

- `crm_activity_fields_json`, emits `salesloft.crm_activity_fields_json`, reads `/v2/crm_activity_fields.json`
- `account_stages_json`, emits `salesloft.account_stages_json`, reads `/v2/account_stages.json`
- `cadence_memberships_json`, emits `salesloft.cadence_memberships_json`, reads `/v2/cadence_memberships.json`
- `groups_json`, emits `salesloft.groups_json`, reads `/v2/groups.json`

## Tests

- `go test ./sources/salesloft ./internal/sourceprojection -count=1`
- `make catalog-check`
