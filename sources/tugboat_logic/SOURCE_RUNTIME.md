# Tugboat Logic

Generated Source Runtime SDK scaffold for `tugboat_logic`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/tugboat_logic`
- Health endpoint: `/source-runtimes/health?source_id=tugboat_logic`
- Source health receipt: `sources/tugboat_logic/source_health_receipt.json`
- EvidenceCAS reference kind: `tugboat_logic.evidence_cas_reference`

## Families

- `assets`, emits `tugboat_logic.assets`, reads `/v1/assets`
- `findings`, emits `tugboat_logic.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `tugboat_logic.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `tugboat_logic.policies`, reads `/v1/policies`
- `audit_events`, emits `tugboat_logic.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/tugboat_logic ./internal/sourceprojection -count=1`
- `make catalog-check`
