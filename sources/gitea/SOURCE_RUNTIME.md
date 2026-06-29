# Gitea

Generated Source Runtime SDK scaffold for `gitea`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/gitea`
- Health endpoint: `/source-runtimes/health?source_id=gitea`
- Source health receipt: `sources/gitea/source_health_receipt.json`
- EvidenceCAS reference kind: `gitea.evidence_cas_reference`

## Families

- `search`, emits `gitea.search`, reads `/repos/issues/search`
- `email`, emits `gitea.email`, reads `/user/emails`
- `team`, emits `gitea.team`, reads `/user/teams`
- `timeline`, emits `gitea.timeline`, reads `/repos/${config.owner}/${config.repo}/issues/${config.index}/timeline`

## Tests

- `go test ./sources/gitea ./internal/sourceprojection -count=1`
- `make catalog-check`
