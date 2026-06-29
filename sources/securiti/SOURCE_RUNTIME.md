# Securiti

Generated Source Runtime SDK scaffold for `securiti`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/securiti`
- Health endpoint: `/source-runtimes/health?source_id=securiti`
- Source health receipt: `sources/securiti/source_health_receipt.json`
- EvidenceCAS reference kind: `securiti.evidence_cas_reference`

## Families

- `assets`, emits `securiti.assets`, reads `/v1/assets`
- `findings`, emits `securiti.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `securiti.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `securiti.policies`, reads `/v1/policies`
- `audit_events`, emits `securiti.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/securiti ./internal/sourceprojection -count=1`
- `make catalog-check`
