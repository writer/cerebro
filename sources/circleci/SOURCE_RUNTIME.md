# CircleCI

Generated Source Runtime SDK scaffold for `circleci`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/circleci`
- Health endpoint: `/source-runtimes/health?source_id=circleci`
- Source health receipt: `sources/circleci/source_health_receipt.json`
- EvidenceCAS reference kind: `circleci.evidence_cas_reference`

## Families

- `pipelines`, emits `circleci.pipelines`, reads `/v1/pipelines`
- `findings`, emits `circleci.findings`, reads `/v1/findings`
- `audit_events`, emits `circleci.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/circleci ./internal/sourceprojection -count=1`
- `make catalog-check`
