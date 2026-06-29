# Cyera

Generated Source Runtime SDK scaffold for `cyera`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cyera`
- Health endpoint: `/source-runtimes/health?source_id=cyera`
- Source health receipt: `sources/cyera/source_health_receipt.json`
- EvidenceCAS reference kind: `cyera.evidence_cas_reference`

## Families

- `assets`, emits `cyera.assets`, reads `/v1/assets`
- `findings`, emits `cyera.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `cyera.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `cyera.policies`, reads `/v1/policies`
- `audit_events`, emits `cyera.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cyera ./internal/sourceprojection -count=1`
- `make catalog-check`
