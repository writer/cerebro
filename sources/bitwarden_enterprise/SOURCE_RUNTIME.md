# Bitwarden Enterprise

Generated Source Runtime SDK scaffold for `bitwarden_enterprise`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bitwarden_enterprise`
- Health endpoint: `/source-runtimes/health?source_id=bitwarden_enterprise`
- Source health receipt: `sources/bitwarden_enterprise/source_health_receipt.json`
- EvidenceCAS reference kind: `bitwarden_enterprise.evidence_cas_reference`

## Families

- `users`, emits `bitwarden_enterprise.users`, reads `/v1/users`
- `secrets`, emits `bitwarden_enterprise.secrets`, reads `/v1/secrets`
- `audit_events`, emits `bitwarden_enterprise.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/bitwarden_enterprise ./internal/sourceprojection -count=1`
- `make catalog-check`
