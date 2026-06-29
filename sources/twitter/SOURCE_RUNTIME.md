# Twitter

Generated Source Runtime SDK scaffold for `twitter`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/twitter`
- Health endpoint: `/source-runtimes/health?source_id=twitter`
- Source health receipt: `sources/twitter/source_health_receipt.json`
- EvidenceCAS reference kind: `twitter.evidence_cas_reference`

## Families

- `list_membership`, emits `twitter.list_membership`, reads `/2/users/${config.id}/list_memberships`
- `member`, emits `twitter.member`, reads `/2/lists/${config.id}/members`
- `job`, emits `twitter.job`, reads `/2/compliance/jobs`
- `dm_event`, emits `twitter.dm_event`, reads `/2/dm_events`

## Tests

- `go test ./sources/twitter ./internal/sourceprojection -count=1`
- `make catalog-check`
