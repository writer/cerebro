# Logicgate

Generated Source Runtime SDK scaffold for `logicgate`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/logicgate`
- Health endpoint: `/source-runtimes/health?source_id=logicgate`
- Source health receipt: `sources/logicgate/source_health_receipt.json`
- EvidenceCAS reference kind: `logicgate.evidence_cas_reference`

## Families

- `assets`, emits `logicgate.assets`, reads `/v1/assets`
- `findings`, emits `logicgate.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `logicgate.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `logicgate.policies`, reads `/v1/policies`
- `audit_events`, emits `logicgate.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/logicgate ./internal/sourceprojection -count=1`
- `make catalog-check`
