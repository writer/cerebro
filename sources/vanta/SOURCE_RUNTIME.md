# Vanta

Generated Source Runtime SDK scaffold for `vanta`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/vanta`
- Health endpoint: `/source-runtimes/health?source_id=vanta`
- Source health receipt: `sources/vanta/source_health_receipt.json`
- EvidenceCAS reference kind: `vanta.evidence_cas_reference`

## Families

- `users`, emits `vanta.users`, reads `/v1/users`
- `controls`, emits `vanta.controls`, reads `/v1/controls`
- `findings`, emits `vanta.findings`, reads `/v1/findings`

## Tests

- `go test ./sources/vanta ./internal/sourceprojection -count=1`
- `make catalog-check`
