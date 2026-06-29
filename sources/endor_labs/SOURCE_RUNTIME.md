# Endor Labs

Generated Source Runtime SDK scaffold for `endor_labs`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/endor_labs`
- Health endpoint: `/source-runtimes/health?source_id=endor_labs`
- Source health receipt: `sources/endor_labs/source_health_receipt.json`
- EvidenceCAS reference kind: `endor_labs.evidence_cas_reference`

## Families

- `assets`, emits `endor_labs.assets`, reads `/v1/assets`
- `findings`, emits `endor_labs.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `endor_labs.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `endor_labs.policies`, reads `/v1/policies`
- `audit_events`, emits `endor_labs.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/endor_labs ./internal/sourceprojection -count=1`
- `make catalog-check`
