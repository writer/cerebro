# InfluxDB

Generated Source Runtime SDK scaffold for `influxdata`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/influxdata`
- Health endpoint: `/source-runtimes/health?source_id=influxdata`
- Source health receipt: `sources/influxdata/source_health_receipt.json`
- EvidenceCAS reference kind: `influxdata.evidence_cas_reference`

## Families

- `log`, emits `influxdata.log`, reads `/tasks/${config.taskid}/logs`
- `user`, emits `influxdata.user`, reads `/users`
- `secret`, emits `influxdata.secret`, reads `/orgs/${config.orgid}/secrets`
- `dbrp`, emits `influxdata.dbrp`, reads `/dbrps`

## Tests

- `go test ./sources/influxdata ./internal/sourceprojection -count=1`
- `make catalog-check`
