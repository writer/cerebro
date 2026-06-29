# OneTrust

Generated Source Runtime SDK scaffold for `onetrust`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/onetrust`
- Health endpoint: `/source-runtimes/health?source_id=onetrust`
- Source health receipt: `sources/onetrust/source_health_receipt.json`
- EvidenceCAS reference kind: `onetrust.evidence_cas_reference`

## Families

- `users`, emits `onetrust.users`, reads `/v1/users`
- `controls`, emits `onetrust.controls`, reads `/v1/controls`
- `findings`, emits `onetrust.findings`, reads `/v1/findings`

## Tests

- `go test ./sources/onetrust ./internal/sourceprojection -count=1`
- `make catalog-check`
