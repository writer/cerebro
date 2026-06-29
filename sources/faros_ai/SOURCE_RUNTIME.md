# Faros Ai

Generated Source Runtime SDK scaffold for `faros_ai`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/faros_ai`
- Health endpoint: `/source-runtimes/health?source_id=faros_ai`
- Source health receipt: `sources/faros_ai/source_health_receipt.json`
- EvidenceCAS reference kind: `faros_ai.evidence_cas_reference`

## Families

- `assets`, emits `faros_ai.assets`, reads `/v1/assets`
- `findings`, emits `faros_ai.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `faros_ai.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `faros_ai.policies`, reads `/v1/policies`
- `audit_events`, emits `faros_ai.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/faros_ai ./internal/sourceprojection -count=1`
- `make catalog-check`
