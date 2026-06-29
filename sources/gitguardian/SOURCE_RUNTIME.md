# GitGuardian

Generated Source Runtime SDK scaffold for `gitguardian`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/gitguardian`
- Health endpoint: `/source-runtimes/health?source_id=gitguardian`
- Source health receipt: `sources/gitguardian/source_health_receipt.json`
- EvidenceCAS reference kind: `gitguardian.evidence_cas_reference`

## Families

- `incidents`, emits `gitguardian.incidents`, reads `/v1/incidents/secrets`
- `members`, emits `gitguardian.members`, reads `/v1/members`
- `audit_events`, emits `gitguardian.audit_events`, reads `/v1/audit_logs`

## Tests

- `go test ./sources/gitguardian ./internal/sourceprojection -count=1`
- `make catalog-check`
