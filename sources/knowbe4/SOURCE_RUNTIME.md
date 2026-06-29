# KnowBe4

Generated Source Runtime SDK scaffold for `knowbe4`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/knowbe4`
- Health endpoint: `/source-runtimes/health?source_id=knowbe4`
- Source health receipt: `sources/knowbe4/source_health_receipt.json`
- EvidenceCAS reference kind: `knowbe4.evidence_cas_reference`

## Families

- `users`, emits `knowbe4.users`, reads `/users`
- `groups`, emits `knowbe4.groups`, reads `/groups`
- `training_enrollments`, emits `knowbe4.training_enrollments`, reads `/training/enrollments`
- `phishing_campaigns`, emits `knowbe4.phishing_campaigns`, reads `/phishing/campaigns`

## Tests

- `go test ./sources/knowbe4 ./internal/sourceprojection -count=1`
- `make catalog-check`
