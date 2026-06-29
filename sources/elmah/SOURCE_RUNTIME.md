# elmah.io

Generated Source Runtime SDK scaffold for `elmah`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/elmah`
- Health endpoint: `/source-runtimes/health?source_id=elmah`
- Source health receipt: `sources/elmah/source_health_receipt.json`
- EvidenceCAS reference kind: `elmah.evidence_cas_reference`

## Families

- `log`, emits `elmah.log`, reads `/v3/logs`
- `deployment`, emits `elmah.deployment`, reads `/v3/deployments`
- `uptimecheck`, emits `elmah.uptimecheck`, reads `/v3/uptimechecks`
- `message`, emits `elmah.message`, reads `/v3/messages/${config.logid}`

## Tests

- `go test ./sources/elmah ./internal/sourceprojection -count=1`
- `make catalog-check`
