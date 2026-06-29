# Opendatasoft

Generated Source Runtime SDK scaffold for `opendatasoft`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/opendatasoft`
- Health endpoint: `/source-runtimes/health?source_id=opendatasoft`
- Source health receipt: `sources/opendatasoft/source_health_receipt.json`
- EvidenceCAS reference kind: `opendatasoft.evidence_cas_reference`

## Families

- `aggregate`, emits `opendatasoft.aggregate`, reads `/${config.source}/aggregates`
- `page`, emits `opendatasoft.page`, reads `/pages`
- `dataset`, emits `opendatasoft.dataset`, reads `/${config.source}/datasets`
- `facet`, emits `opendatasoft.facet`, reads `/${config.source}/facets`
- `resource`, emits `opendatasoft.resource`, reads `/${config.source}`
- `resource_2`, emits `opendatasoft.resource_2`, reads `/`
- `metadata_template`, emits `opendatasoft.metadata_template`, reads `/${config.source}/metadata_templates`
- `datasets_aggregate`, emits `opendatasoft.datasets_aggregate`, reads `/${config.source}/datasets/${config.dataset_id}/aggregates`
- `attachment`, emits `opendatasoft.attachment`, reads `/${config.source}/datasets/${config.dataset_id}/attachments`
- `datasets_facet`, emits `opendatasoft.datasets_facet`, reads `/${config.source}/datasets/${config.dataset_id}/facets`
- `record`, emits `opendatasoft.record`, reads `/${config.source}/datasets/${config.dataset_id}/records`
- `reuses`, emits `opendatasoft.reuses`, reads `/${config.source}/datasets/${config.dataset_id}/reuses`

## Tests

- `go test ./sources/opendatasoft ./internal/sourceprojection -count=1`
- `make catalog-check`
