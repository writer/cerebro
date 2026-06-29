# Invicti

Generated Source Runtime SDK scaffold for `invicti`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/invicti`
- Health endpoint: `/source-runtimes/health?source_id=invicti`
- Source health receipt: `sources/invicti/source_health_receipt.json`
- EvidenceCAS reference kind: `invicti.evidence_cas_reference`

## Families

- `assets`, emits `invicti.assets`, reads `/v1/assets`
- `findings`, emits `invicti.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `invicti.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `invicti.policies`, reads `/v1/policies`
- `audit_events`, emits `invicti.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/invicti ./internal/sourceprojection -count=1`
- `make catalog-check`
