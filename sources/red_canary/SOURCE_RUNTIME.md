# Red Canary

Generated Source Runtime SDK scaffold for `red_canary`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/red_canary`
- Health endpoint: `/source-runtimes/health?source_id=red_canary`
- Source health receipt: `sources/red_canary/source_health_receipt.json`
- EvidenceCAS reference kind: `red_canary.evidence_cas_reference`

## Families

- `assets`, emits `red_canary.assets`, reads `/v1/assets`
- `findings`, emits `red_canary.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `red_canary.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `red_canary.policies`, reads `/v1/policies`
- `audit_events`, emits `red_canary.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/red_canary ./internal/sourceprojection -count=1`
- `make catalog-check`
