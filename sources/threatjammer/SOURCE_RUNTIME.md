# ThreatJammer

Generated Source Runtime SDK scaffold for `threatjammer`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/threatjammer`
- Health endpoint: `/source-runtimes/health?source_id=threatjammer`
- Source health receipt: `sources/threatjammer/source_health_receipt.json`
- EvidenceCAS reference kind: `threatjammer.evidence_cas_reference`

## Families

- `activity`, emits `threatjammer.activity`, reads `/v1/token/activity`
- `all`, emits `threatjammer.all`, reads `/v1/origin_token/all`
- `ip`, emits `threatjammer.ip`, reads `/v1/assess/ip/${config.ip_address}`
- `reported_ip`, emits `threatjammer.reported_ip`, reads `/v1/denylist/reported/ip`

## Tests

- `go test ./sources/threatjammer ./internal/sourceprojection -count=1`
- `make catalog-check`
