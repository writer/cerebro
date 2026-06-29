# Servicenow GRC

Generated Source Runtime SDK scaffold for `servicenow_grc`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/servicenow_grc`
- Health endpoint: `/source-runtimes/health?source_id=servicenow_grc`
- Source health receipt: `sources/servicenow_grc/source_health_receipt.json`
- EvidenceCAS reference kind: `servicenow_grc.evidence_cas_reference`

## Families

- `assets`, emits `servicenow_grc.assets`, reads `/v1/assets`
- `findings`, emits `servicenow_grc.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `servicenow_grc.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `servicenow_grc.policies`, reads `/v1/policies`
- `audit_events`, emits `servicenow_grc.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/servicenow_grc ./internal/sourceprojection -count=1`
- `make catalog-check`
