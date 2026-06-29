# Microsoft Foundry

Generated Source Runtime SDK scaffold for `microsoft_foundry`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/microsoft_foundry`
- Health endpoint: `/source-runtimes/health?source_id=microsoft_foundry`
- Source health receipt: `sources/microsoft_foundry/source_health_receipt.json`
- EvidenceCAS reference kind: `microsoft_foundry.evidence_cas_reference`

## Families

- `agents`, emits `microsoft_foundry.agents`, reads `/agents`
- `datasets`, emits `microsoft_foundry.datasets`, reads `/datasets`
- `indexes`, emits `microsoft_foundry.indexes`, reads `/indexes`
- `evaluations`, emits `microsoft_foundry.evaluations`, reads `/evaluations`
- `connections`, emits `microsoft_foundry.connections`, reads `/connections`

## Tests

- `go test ./sources/microsoft_foundry ./internal/sourceprojection -count=1`
- `make catalog-check`
