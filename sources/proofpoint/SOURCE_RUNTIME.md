# Proofpoint

Generated Source Runtime SDK scaffold for `proofpoint`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/proofpoint`
- Health endpoint: `/source-runtimes/health?source_id=proofpoint`
- Source health receipt: `sources/proofpoint/source_health_receipt.json`
- EvidenceCAS reference kind: `proofpoint.evidence_cas_reference`

## Families

- `assets`, emits `proofpoint.assets`, reads `/v1/assets`
- `findings`, emits `proofpoint.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `proofpoint.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `proofpoint.policies`, reads `/v1/policies`
- `audit_events`, emits `proofpoint.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/proofpoint ./internal/sourceprojection -count=1`
- `make catalog-check`
