# Mailscript

Generated Source Runtime SDK scaffold for `mailscript`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mailscript`
- Health endpoint: `/source-runtimes/health?source_id=mailscript`
- Source health receipt: `sources/mailscript/source_health_receipt.json`
- EvidenceCAS reference kind: `mailscript.evidence_cas_reference`

## Families

- `workspace`, emits `mailscript.workspace`, reads `/workspaces`
- `workflow`, emits `mailscript.workflow`, reads `/workflows`
- `key`, emits `mailscript.key`, reads `/addresses/${config.address}/keys`
- `action`, emits `mailscript.action`, reads `/actions`
- `addresses`, emits `mailscript.addresses`, reads `/addresses`
- `domain`, emits `mailscript.domain`, reads `/domains`
- `input`, emits `mailscript.input`, reads `/inputs`
- `integration`, emits `mailscript.integration`, reads `/integrations`
- `trigger`, emits `mailscript.trigger`, reads `/triggers`
- `verification`, emits `mailscript.verification`, reads `/verifications`
- `verify`, emits `mailscript.verify`, reads `/domains/verify/${config.domain}`

## Tests

- `go test ./sources/mailscript ./internal/sourceprojection -count=1`
- `make catalog-check`
