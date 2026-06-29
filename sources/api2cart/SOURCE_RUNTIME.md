# API2Cart

Generated Source Runtime SDK scaffold for `api2cart`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/api2cart`
- Health endpoint: `/source-runtimes/health?source_id=api2cart`
- Source health receipt: `sources/api2cart/source_health_receipt.json`
- EvidenceCAS reference kind: `api2cart.evidence_cas_reference`

## Families

- `attribute_group_list_json`, emits `api2cart.attribute_group_list_json`, reads `/attribute.group.list.json`
- `attribute_attributeset_list_json`, emits `api2cart.attribute_attributeset_list_json`, reads `/attribute.attributeset.list.json`

## Tests

- `go test ./sources/api2cart ./internal/sourceprojection -count=1`
- `make catalog-check`
