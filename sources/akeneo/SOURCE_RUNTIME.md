# Akeneo

Generated Source Runtime SDK scaffold for `akeneo`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/akeneo`
- Health endpoint: `/source-runtimes/health?source_id=akeneo`
- Source health receipt: `sources/akeneo/source_health_receipt.json`
- EvidenceCAS reference kind: `akeneo.evidence_cas_reference`

## Families

- `attribute`, emits `akeneo.attribute`, reads `/api/rest/v1/asset-families/${config.asset_family_code}/attributes`
- `attribute_group`, emits `akeneo.attribute_group`, reads `/api/rest/v1/attribute-groups/${config.code}`
- `option`, emits `akeneo.option`, reads `/api/rest/v1/asset-families/${config.asset_family_code}/attributes/${config.attribute_code}/options`
- `reference_entities_attribute`, emits `akeneo.reference_entities_attribute`, reads `/api/rest/v1/reference-entities/${config.reference_entity_code}/attributes`
- `attributes_option`, emits `akeneo.attributes_option`, reads `/api/rest/v1/reference-entities/${config.reference_entity_code}/attributes/${config.attribute_code}/options`
- `asset`, emits `akeneo.asset`, reads `/api/rest/v1/assets/${config.code}`
- `asset_family`, emits `akeneo.asset_family`, reads `/api/rest/v1/asset-families/${config.code}`
- `draft`, emits `akeneo.draft`, reads `/api/rest/v1/product-models/${config.code}/draft`
- `products_uuid_draft`, emits `akeneo.products_uuid_draft`, reads `/api/rest/v1/products-uuid/${config.uuid}/draft`
- `products_draft`, emits `akeneo.products_draft`, reads `/api/rest/v1/products/${config.code}/draft`
- `asset_families_attribute`, emits `akeneo.asset_families_attribute`, reads `/api/rest/v1/asset-families/${config.asset_family_code}/attributes/${config.code}`
- `v1_attribute`, emits `akeneo.v1_attribute`, reads `/api/rest/v1/attributes/${config.code}`

## Tests

- `go test ./sources/akeneo ./internal/sourceprojection -count=1`
- `make catalog-check`
