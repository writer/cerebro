# ClickMeter

Generated Source Runtime SDK scaffold for `clickmeter`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/clickmeter`
- Health endpoint: `/source-runtimes/health?source_id=clickmeter`
- Source health receipt: `sources/clickmeter/source_health_receipt.json`
- EvidenceCAS reference kind: `clickmeter.evidence_cas_reference`

## Families

- `clickstream`, emits `clickmeter.clickstream`, reads `/clickstream`
- `group`, emits `clickmeter.group`, reads `/groups`
- `list`, emits `clickmeter.list`, reads `/groups/aggregated/list`
- `hit`, emits `clickmeter.hit`, reads `/hits`
- `ipblacklist`, emits `clickmeter.ipblacklist`, reads `/account/ipblacklist`
- `conversions_hit`, emits `clickmeter.conversions_hit`, reads `/conversions/${config.conversionid}/hits`
- `datapoints_hit`, emits `clickmeter.datapoints_hit`, reads `/datapoints/${config.id}/hits`
- `groups_hit`, emits `clickmeter.groups_hit`, reads `/groups/${config.id}/hits`
- `tags_group`, emits `clickmeter.tags_group`, reads `/tags/${config.tagid}/groups`
- `summary_group`, emits `clickmeter.summary_group`, reads `/aggregated/summary/groups`
- `datapoint`, emits `clickmeter.datapoint`, reads `/groups/${config.id}/datapoints`
- `aggregated_list`, emits `clickmeter.aggregated_list`, reads `/groups/${config.id}/aggregated/list`

## Tests

- `go test ./sources/clickmeter ./internal/sourceprojection -count=1`
- `make catalog-check`
