# Bugcrowd

Generated Source Runtime SDK scaffold for `bugcrowd`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bugcrowd`
- Health endpoint: `/source-runtimes/health?source_id=bugcrowd`
- Source health receipt: `sources/bugcrowd/source_health_receipt.json`
- EvidenceCAS reference kind: `bugcrowd.evidence_cas_reference`

## Families

- `assets`, emits `bugcrowd.assets`, reads `/v1/assets`
- `findings`, emits `bugcrowd.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `bugcrowd.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `bugcrowd.policies`, reads `/v1/policies`
- `audit_events`, emits `bugcrowd.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/bugcrowd ./internal/sourceprojection -count=1`
- `make catalog-check`
