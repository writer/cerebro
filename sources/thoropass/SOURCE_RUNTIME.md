# Thoropass

Generated Source Runtime SDK scaffold for `thoropass`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/thoropass`
- Health endpoint: `/source-runtimes/health?source_id=thoropass`
- Source health receipt: `sources/thoropass/source_health_receipt.json`
- EvidenceCAS reference kind: `thoropass.evidence_cas_reference`

## Families

- `assets`, emits `thoropass.assets`, reads `/v1/assets`
- `findings`, emits `thoropass.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `thoropass.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `thoropass.policies`, reads `/v1/policies`
- `audit_events`, emits `thoropass.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/thoropass ./internal/sourceprojection -count=1`
- `make catalog-check`
