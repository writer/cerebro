# Appomni

Generated Source Runtime SDK scaffold for `appomni`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/appomni`
- Health endpoint: `/source-runtimes/health?source_id=appomni`
- Source health receipt: `sources/appomni/source_health_receipt.json`
- EvidenceCAS reference kind: `appomni.evidence_cas_reference`

## Families

- `assets`, emits `appomni.assets`, reads `/v1/assets`
- `findings`, emits `appomni.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `appomni.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `appomni.policies`, reads `/v1/policies`
- `audit_events`, emits `appomni.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/appomni ./internal/sourceprojection -count=1`
- `make catalog-check`
