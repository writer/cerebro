# Cenit

Generated Source Runtime SDK scaffold for `cenit`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cenit`
- Health endpoint: `/source-runtimes/health?source_id=cenit`
- Source health receipt: `sources/cenit/source_health_receipt.json`
- EvidenceCAS reference kind: `cenit.evidence_cas_reference`

## Families

- `observer`, emits `cenit.observer`, reads `/setup/observer/`
- `connection_role`, emits `cenit.connection_role`, reads `/setup/connection_role`
- `webhook`, emits `cenit.webhook`, reads `/setup/webhook/`
- `connection`, emits `cenit.connection`, reads `/setup/connection`
- `data_type`, emits `cenit.data_type`, reads `/setup/data_type/`
- `flow`, emits `cenit.flow`, reads `/setup/flow/`
- `namespace`, emits `cenit.namespace`, reads `/setup/namespace/`
- `scheduler`, emits `cenit.scheduler`, reads `/setup/scheduler/`
- `schema`, emits `cenit.schema`, reads `/setup/schema/`
- `translator`, emits `cenit.translator`, reads `/setup/translator/`
- `setup_connection_role`, emits `cenit.setup_connection_role`, reads `/setup/connection_role/${config.id}`
- `setup_webhook`, emits `cenit.setup_webhook`, reads `/setup/webhook/${config.id}`

## Tests

- `go test ./sources/cenit ./internal/sourceprojection -count=1`
- `make catalog-check`
