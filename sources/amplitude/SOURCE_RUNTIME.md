# Amplitude

Provider-verified Source Runtime SDK for `amplitude`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Auth mechanics: SCIM token in the `Authorization: Bearer <token>` header
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/amplitude`
- Health endpoint: `/source-runtimes/health?source_id=amplitude`
- Source health receipt: `sources/amplitude/source_health_receipt.json`
- EvidenceCAS reference kind: `amplitude.evidence_cas_reference`

## Families

- `users`, emits `amplitude.users`, reads `GET /scim/1/Users`
- `groups`, emits `amplitude.groups`, reads `GET /scim/1/Groups`

## Tests

- `go test ./sources/amplitude ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/amplitude/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
