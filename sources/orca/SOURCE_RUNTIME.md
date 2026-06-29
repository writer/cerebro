# Orca

Generated Source Runtime SDK scaffold for `orca`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/orca`
- Health endpoint: `/source-runtimes/health?source_id=orca`
- Source health receipt: `sources/orca/source_health_receipt.json`
- EvidenceCAS reference kind: `orca.evidence_cas_reference`

## Families

- `assets`, emits `orca.assets`, reads `/v1/assets`
- `findings`, emits `orca.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `orca.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/orca ./internal/sourceprojection -count=1`
- `make catalog-check`
