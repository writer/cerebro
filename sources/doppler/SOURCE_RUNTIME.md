# Doppler

Generated Source Runtime SDK scaffold for `doppler`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/doppler`
- Health endpoint: `/source-runtimes/health?source_id=doppler`
- Source health receipt: `sources/doppler/source_health_receipt.json`
- EvidenceCAS reference kind: `doppler.evidence_cas_reference`

## Families

- `secrets`, emits `doppler.secrets`, reads `/v3/workplace/secrets`
- `projects`, emits `doppler.projects`, reads `/v3/workplace/projects`
- `audit_events`, emits `doppler.audit_events`, reads `/v3/workplace/logs`

## Tests

- `go test ./sources/doppler ./internal/sourceprojection -count=1`
- `make catalog-check`
