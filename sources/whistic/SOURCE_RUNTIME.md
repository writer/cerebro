# Whistic

Generated Source Runtime SDK scaffold for `whistic`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/whistic`
- Health endpoint: `/source-runtimes/health?source_id=whistic`
- Source health receipt: `sources/whistic/source_health_receipt.json`
- EvidenceCAS reference kind: `whistic.evidence_cas_reference`

## Families

- `assets`, emits `whistic.assets`, reads `/v1/assets`
- `findings`, emits `whistic.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `whistic.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `whistic.policies`, reads `/v1/policies`
- `audit_events`, emits `whistic.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/whistic ./internal/sourceprojection -count=1`
- `make catalog-check`
