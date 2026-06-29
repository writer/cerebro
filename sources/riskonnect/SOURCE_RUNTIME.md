# Riskonnect

Generated Source Runtime SDK scaffold for `riskonnect`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/riskonnect`
- Health endpoint: `/source-runtimes/health?source_id=riskonnect`
- Source health receipt: `sources/riskonnect/source_health_receipt.json`
- EvidenceCAS reference kind: `riskonnect.evidence_cas_reference`

## Families

- `assets`, emits `riskonnect.assets`, reads `/v1/assets`
- `findings`, emits `riskonnect.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `riskonnect.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `riskonnect.policies`, reads `/v1/policies`
- `audit_events`, emits `riskonnect.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/riskonnect ./internal/sourceprojection -count=1`
- `make catalog-check`
