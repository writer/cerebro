# Argo CD

Generated Source Runtime SDK scaffold for `argo_cd`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/argo_cd`
- Health endpoint: `/source-runtimes/health?source_id=argo_cd`
- Source health receipt: `sources/argo_cd/source_health_receipt.json`
- EvidenceCAS reference kind: `argo_cd.evidence_cas_reference`

## Families

- `pipelines`, emits `argo_cd.pipelines`, reads `/v1/pipelines`
- `findings`, emits `argo_cd.findings`, reads `/v1/findings`
- `audit_events`, emits `argo_cd.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/argo_cd ./internal/sourceprojection -count=1`
- `make catalog-check`
