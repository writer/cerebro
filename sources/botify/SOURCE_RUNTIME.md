# Botify

Generated Source Runtime SDK scaffold for `botify`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/botify`
- Health endpoint: `/source-runtimes/health?source_id=botify`
- Source health receipt: `sources/botify/source_health_receipt.json`
- EvidenceCAS reference kind: `botify.evidence_cas_reference`

## Families

- `filter`, emits `botify.filter`, reads `/projects/${config.username}/${config.project_slug}/filters`
- `export`, emits `botify.export`, reads `/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/urls/export`
- `out_of_config`, emits `botify.out_of_config`, reads `/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/features/sitemaps/samples/out_of_config`
- `sitemap_only`, emits `botify.sitemap_only`, reads `/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/features/sitemaps/samples/sitemap_only`
- `report`, emits `botify.report`, reads `/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/features/sitemaps/report`
- `project`, emits `botify.project`, reads `/projects/${config.username}`
- `analyses`, emits `botify.analyses`, reads `/analyses/${config.username}/${config.project_slug}`
- `url`, emits `botify.url`, reads `/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/crawl_statistics/urls/${config.list_type}`
- `orphan_url`, emits `botify.orphan_url`, reads `/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/features/ganalytics/orphan_urls/${config.medium}/${config.source}`
- `datamodel`, emits `botify.datamodel`, reads `/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/urls/datamodel`
- `domain`, emits `botify.domain`, reads `/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/features/top_domains/domains`
- `percentile`, emits `botify.percentile`, reads `/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/features/links/percentiles`

## Tests

- `go test ./sources/botify ./internal/sourceprojection -count=1`
- `make catalog-check`
