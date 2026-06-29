# Traceable Ai

Generated Source Runtime SDK scaffold for `traceable_ai`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/traceable_ai`
- Health endpoint: `/source-runtimes/health?source_id=traceable_ai`
- Source health receipt: `sources/traceable_ai/source_health_receipt.json`
- EvidenceCAS reference kind: `traceable_ai.evidence_cas_reference`

## Families

- `assets`, emits `traceable_ai.assets`, reads `/v1/assets`
- `findings`, emits `traceable_ai.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `traceable_ai.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `traceable_ai.policies`, reads `/v1/policies`
- `audit_events`, emits `traceable_ai.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/traceable_ai ./internal/sourceprojection -count=1`
- `make catalog-check`
