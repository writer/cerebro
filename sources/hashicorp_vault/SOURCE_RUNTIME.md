# HashiCorp Vault

Source Runtime adapter for Vault identity entities, mounted secret engines, and enabled audit devices.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Auth mechanics: `X-Vault-Token`
- Base URL: configured Vault address
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hashicorp_vault`
- Health endpoint: `/source-runtimes/health?source_id=hashicorp_vault`
- Source health receipt: `sources/hashicorp_vault/source_health_receipt.json`
- Emits identity entities, mounted secret engine inventory, and audit device configuration evidence.

## Families

- `users`, emits `hashicorp_vault.users`, reads `GET /v1/identity/entity/id` with `list=true`
- `secrets`, emits `hashicorp_vault.secrets`, reads `GET /v1/sys/mounts`
- `audit_events`, emits `hashicorp_vault.audit_events`, reads `GET /v1/sys/audit`

`secrets` represents mounted secret engines, not secret values. `audit_events` represents enabled audit device configuration because Vault emits audit logs to configured devices instead of exposing a generic audit-event read endpoint.

## Tests

- `go test ./sources/hashicorp_vault ./internal/sourceprojection -count=1`
- `make lint-sources catalog-check sourcegen-check check-structural check-structural-test check-arch`
- `make connector-catalog-review connector-api-discovery`
