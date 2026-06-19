# HashiCorp Vault

Generated Source Runtime SDK scaffold for `hashicorp_vault`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hashicorp_vault`
- Health endpoint: `/source-runtimes/health?source_id=hashicorp_vault`
- Source health receipt: `sources/hashicorp_vault/source_health_receipt.json`
- EvidenceCAS reference kind: `hashicorp_vault.evidence_cas_reference`

## Families

- `users`, emits `hashicorp_vault.users`, reads `/v1/users`
- `secrets`, emits `hashicorp_vault.secrets`, reads `/v1/secrets`
- `audit_events`, emits `hashicorp_vault.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/hashicorp_vault ./internal/sourceprojection -count=1`
- `make catalog-check`
