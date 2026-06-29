# Appwrite

Generated Source Runtime SDK scaffold for `appwrite`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/appwrite`
- Health endpoint: `/source-runtimes/health?source_id=appwrite`
- Source health receipt: `sources/appwrite/source_health_receipt.json`
- EvidenceCAS reference kind: `appwrite.evidence_cas_reference`

## Families

- `team`, emits `appwrite.team`, reads `/teams`
- `log`, emits `appwrite.log`, reads `/account/logs`
- `membership`, emits `appwrite.membership`, reads `/teams/${config.teamid}/memberships`
- `continent`, emits `appwrite.continent`, reads `/locale/continents`

## Tests

- `go test ./sources/appwrite ./internal/sourceprojection -count=1`
- `make catalog-check`
