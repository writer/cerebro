# AuditBoard

Generated Source Runtime SDK scaffold for `auditboard`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/auditboard`
- Health endpoint: `/source-runtimes/health?source_id=auditboard`
- Source health receipt: `sources/auditboard/source_health_receipt.json`
- EvidenceCAS reference kind: `auditboard.evidence_cas_reference`

## Families

- `users`, emits `auditboard.users`, reads `/v1/users`
- `controls`, emits `auditboard.controls`, reads `/v1/controls`
- `findings`, emits `auditboard.findings`, reads `/v1/findings`

## Tests

- `go test ./sources/auditboard ./internal/sourceprojection -count=1`
- `make catalog-check`
