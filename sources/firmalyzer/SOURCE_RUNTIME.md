# Firmalyzer IoTVAS

Generated Source Runtime SDK scaffold for `firmalyzer`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/firmalyzer`
- Health endpoint: `/source-runtimes/health?source_id=firmalyzer`
- Source health receipt: `sources/firmalyzer/source_health_receipt.json`
- EvidenceCAS reference kind: `firmalyzer.evidence_cas_reference`

## Families

- `config_issue`, emits `firmalyzer.config_issue`, reads `/firmware/${config.firmware_hash}/config-issues`
- `account`, emits `firmalyzer.account`, reads `/firmware/${config.firmware_hash}/accounts`
- `private_key`, emits `firmalyzer.private_key`, reads `/firmware/${config.firmware_hash}/private-keys`
- `risk`, emits `firmalyzer.risk`, reads `/firmware/${config.firmware_hash}/risk`

## Tests

- `go test ./sources/firmalyzer ./internal/sourceprojection -count=1`
- `make catalog-check`
