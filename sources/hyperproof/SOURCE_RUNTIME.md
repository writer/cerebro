# Hyperproof

Generated Source Runtime SDK scaffold for `hyperproof`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/hyperproof`
- Health endpoint: `/source-runtimes/health?source_id=hyperproof`
- Source health receipt: `sources/hyperproof/source_health_receipt.json`
- EvidenceCAS reference kind: `hyperproof.evidence_cas_reference`

## Families

- `assets`, emits `hyperproof.assets`, reads `/v1/assets`
- `findings`, emits `hyperproof.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `hyperproof.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `hyperproof.policies`, reads `/v1/policies`
- `audit_events`, emits `hyperproof.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/hyperproof ./internal/sourceprojection -count=1`
- `make catalog-check`
