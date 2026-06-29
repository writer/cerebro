# Safe Base

Generated Source Runtime SDK scaffold for `safe_base`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/safe_base`
- Health endpoint: `/source-runtimes/health?source_id=safe_base`
- Source health receipt: `sources/safe_base/source_health_receipt.json`
- EvidenceCAS reference kind: `safe_base.evidence_cas_reference`

## Families

- `assets`, emits `safe_base.assets`, reads `/v1/assets`
- `findings`, emits `safe_base.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `safe_base.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `safe_base.policies`, reads `/v1/policies`
- `audit_events`, emits `safe_base.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/safe_base ./internal/sourceprojection -count=1`
- `make catalog-check`
