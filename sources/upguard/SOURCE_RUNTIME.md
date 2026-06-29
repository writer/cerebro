# Upguard

Generated Source Runtime SDK scaffold for `upguard`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/upguard`
- Health endpoint: `/source-runtimes/health?source_id=upguard`
- Source health receipt: `sources/upguard/source_health_receipt.json`
- EvidenceCAS reference kind: `upguard.evidence_cas_reference`

## Families

- `assets`, emits `upguard.assets`, reads `/v1/assets`
- `findings`, emits `upguard.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `upguard.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `upguard.policies`, reads `/v1/policies`
- `audit_events`, emits `upguard.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/upguard ./internal/sourceprojection -count=1`
- `make catalog-check`
