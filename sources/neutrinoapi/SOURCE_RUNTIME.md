# Neutrino API

Generated Source Runtime SDK scaffold for `neutrinoapi`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/neutrinoapi`
- Health endpoint: `/source-runtimes/health?source_id=neutrinoapi`
- Source health receipt: `sources/neutrinoapi/source_health_receipt.json`
- EvidenceCAS reference kind: `neutrinoapi.evidence_cas_reference`

## Families

- `ip_blocklist`, emits `neutrinoapi.ip_blocklist`, reads `/ip-blocklist`
- `host_reputation`, emits `neutrinoapi.host_reputation`, reads `/host-reputation`
- `bin_lookup`, emits `neutrinoapi.bin_lookup`, reads `/bin-lookup`
- `geocode_address`, emits `neutrinoapi.geocode_address`, reads `/geocode-address`

## Tests

- `go test ./sources/neutrinoapi ./internal/sourceprojection -count=1`
- `make catalog-check`
