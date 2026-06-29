# ExaVault

Generated Source Runtime SDK scaffold for `exavault`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/exavault`
- Health endpoint: `/source-runtimes/health?source_id=exavault`
- Source health receipt: `sources/exavault/source_health_receipt.json`
- EvidenceCAS reference kind: `exavault.evidence_cas_reference`

## Families

- `email_list`, emits `exavault.email_list`, reads `/email-lists`
- `notification`, emits `exavault.notification`, reads `/notifications`
- `session`, emits `exavault.session`, reads `/activity/session`
- `ssh_key`, emits `exavault.ssh_key`, reads `/ssh-keys`

## Tests

- `go test ./sources/exavault ./internal/sourceprojection -count=1`
- `make catalog-check`
