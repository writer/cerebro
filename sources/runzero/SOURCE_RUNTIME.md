# Runzero

Generated Source Runtime SDK scaffold for `runzero`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/runzero`
- Health endpoint: `/source-runtimes/health?source_id=runzero`
- Source health receipt: `sources/runzero/source_health_receipt.json`
- EvidenceCAS reference kind: `runzero.evidence_cas_reference`

## Families

- `assets`, emits `runzero.assets`, reads `/v1/assets`
- `findings`, emits `runzero.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `runzero.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `runzero.policies`, reads `/v1/policies`
- `audit_events`, emits `runzero.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/runzero ./internal/sourceprojection -count=1`
- `make catalog-check`
