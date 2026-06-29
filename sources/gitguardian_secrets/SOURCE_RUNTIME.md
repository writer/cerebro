# GitGuardian Secrets

Generated Source Runtime SDK scaffold for `gitguardian_secrets`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/gitguardian_secrets`
- Health endpoint: `/source-runtimes/health?source_id=gitguardian_secrets`
- Source health receipt: `sources/gitguardian_secrets/source_health_receipt.json`
- EvidenceCAS reference kind: `gitguardian_secrets.evidence_cas_reference`

## Families

- `secrets`, emits `gitguardian_secrets.secrets`, reads `/v1/secrets`
- `sources`, emits `gitguardian_secrets.sources`, reads `/v1/sources`
- `audit_events`, emits `gitguardian_secrets.audit_events`, reads `/v1/audit_logs`

## Tests

- `go test ./sources/gitguardian_secrets ./internal/sourceprojection -count=1`
- `make catalog-check`
