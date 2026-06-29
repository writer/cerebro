# Heroku

Generated Source Runtime SDK scaffold for `heroku`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/heroku`
- Health endpoint: `/source-runtimes/health?source_id=heroku`
- Source health receipt: `sources/heroku/source_health_receipt.json`
- EvidenceCAS reference kind: `heroku.evidence_cas_reference`

## Families

- `apps`, emits `heroku.apps`, reads `/apps`
- `collaborators`, emits `heroku.collaborators`, reads `/collaborators`
- `audit_events`, emits `heroku.audit_events`, reads `/audit-events`

## Tests

- `go test ./sources/heroku ./internal/sourceprojection -count=1`
- `make catalog-check`
