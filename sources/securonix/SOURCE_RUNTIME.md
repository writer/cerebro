# Securonix

Generated Source Runtime SDK scaffold for `securonix`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/securonix`
- Health endpoint: `/source-runtimes/health?source_id=securonix`
- Source health receipt: `sources/securonix/source_health_receipt.json`
- EvidenceCAS reference kind: `securonix.evidence_cas_reference`

## Families

- `assets`, emits `securonix.assets`, reads `/v1/assets`
- `findings`, emits `securonix.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `securonix.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `securonix.policies`, reads `/v1/policies`
- `audit_events`, emits `securonix.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/securonix ./internal/sourceprojection -count=1`
- `make catalog-check`
