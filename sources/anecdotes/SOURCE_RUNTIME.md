# Anecdotes

Generated Source Runtime SDK scaffold for `anecdotes`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/anecdotes`
- Health endpoint: `/source-runtimes/health?source_id=anecdotes`
- Source health receipt: `sources/anecdotes/source_health_receipt.json`
- EvidenceCAS reference kind: `anecdotes.evidence_cas_reference`

## Families

- `assets`, emits `anecdotes.assets`, reads `/v1/assets`
- `findings`, emits `anecdotes.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `anecdotes.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `anecdotes.policies`, reads `/v1/policies`
- `audit_events`, emits `anecdotes.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/anecdotes ./internal/sourceprojection -count=1`
- `make catalog-check`
