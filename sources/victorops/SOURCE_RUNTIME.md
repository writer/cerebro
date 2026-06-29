# VictorOps

Generated Source Runtime SDK scaffold for `victorops`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/victorops`
- Health endpoint: `/source-runtimes/health?source_id=victorops`
- Source health receipt: `sources/victorops/source_health_receipt.json`
- EvidenceCAS reference kind: `victorops.evidence_cas_reference`

## Families

- `log`, emits `victorops.log`, reads `/api-reporting/v1/team/${config.team}/oncall/log`
- `team`, emits `victorops.team`, reads `/api-public/v1/team`
- `user`, emits `victorops.user`, reads `/api-public/v1/user`
- `incident`, emits `victorops.incident`, reads `/api-reporting/v2/incidents`

## Tests

- `go test ./sources/victorops ./internal/sourceprojection -count=1`
- `make catalog-check`
