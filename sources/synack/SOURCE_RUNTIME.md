# Synack

Generated Source Runtime SDK scaffold for `synack`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/synack`
- Health endpoint: `/source-runtimes/health?source_id=synack`
- Source health receipt: `sources/synack/source_health_receipt.json`
- EvidenceCAS reference kind: `synack.evidence_cas_reference`

## Families

- `assets`, emits `synack.assets`, reads `/v1/assets`
- `findings`, emits `synack.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `synack.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `synack.policies`, reads `/v1/policies`
- `audit_events`, emits `synack.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/synack ./internal/sourceprojection -count=1`
- `make catalog-check`
