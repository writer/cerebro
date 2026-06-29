# Runscope

Generated Source Runtime SDK scaffold for `runscope`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/runscope`
- Health endpoint: `/source-runtimes/health?source_id=runscope`
- Source health receipt: `sources/runscope/source_health_receipt.json`
- EvidenceCAS reference kind: `runscope.evidence_cas_reference`

## Families

- `people`, emits `runscope.people`, reads `/teams/${config.teamid}/people`
- `test`, emits `runscope.test`, reads `/buckets/${config.bucketkey}/tests`
- `bucket`, emits `runscope.bucket`, reads `/buckets`
- `agent`, emits `runscope.agent`, reads `/teams/${config.teamid}/agents`
- `integration`, emits `runscope.integration`, reads `/teams/${config.teamid}/integrations`
- `environment`, emits `runscope.environment`, reads `/buckets/${config.bucketkey}/tests/${config.testid}/environments`
- `metric`, emits `runscope.metric`, reads `/buckets/${config.bucketkey}/tests/${config.testid}/metrics`
- `buckets_test`, emits `runscope.buckets_test`, reads `/buckets/${config.bucketkey}/tests/${config.testid}`

## Tests

- `go test ./sources/runscope ./internal/sourceprojection -count=1`
- `make catalog-check`
