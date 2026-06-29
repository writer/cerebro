# Cycode

Generated Source Runtime SDK scaffold for `cycode`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cycode`
- Health endpoint: `/source-runtimes/health?source_id=cycode`
- Source health receipt: `sources/cycode/source_health_receipt.json`
- EvidenceCAS reference kind: `cycode.evidence_cas_reference`

## Families

- `assets`, emits `cycode.assets`, reads `/v1/assets`
- `findings`, emits `cycode.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `cycode.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `cycode.policies`, reads `/v1/policies`
- `audit_events`, emits `cycode.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cycode ./internal/sourceprojection -count=1`
- `make catalog-check`
