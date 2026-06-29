# Big Red Cloud

Generated Source Runtime SDK scaffold for `bigredcloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bigredcloud`
- Health endpoint: `/source-runtimes/health?source_id=bigredcloud`
- Source health receipt: `sources/bigredcloud/source_health_receipt.json`
- EvidenceCAS reference kind: `bigredcloud.evidence_cas_reference`

## Families

- `account`, emits `bigredcloud.account`, reads `/v1/accounts`
- `ownertypegroup`, emits `bigredcloud.ownertypegroup`, reads `/v1/ownerTypeGroups`
- `analysiscategory`, emits `bigredcloud.analysiscategory`, reads `/v1/analysisCategories`
- `bankaccount`, emits `bigredcloud.bankaccount`, reads `/v1/bankAccounts`

## Tests

- `go test ./sources/bigredcloud ./internal/sourceprojection -count=1`
- `make catalog-check`
