# Jenkins

Generated Source Runtime SDK scaffold for `jenkins`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/jenkins`
- Health endpoint: `/source-runtimes/health?source_id=jenkins`
- Source health receipt: `sources/jenkins/source_health_receipt.json`
- EvidenceCAS reference kind: `jenkins.evidence_cas_reference`

## Families

- `pipelines`, emits `jenkins.pipelines`, reads `/v1/pipelines`
- `findings`, emits `jenkins.findings`, reads `/v1/findings`
- `audit_events`, emits `jenkins.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/jenkins ./internal/sourceprojection -count=1`
- `make catalog-check`
