# Legit Security

Generated Source Runtime SDK scaffold for `legit_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/legit_security`
- Health endpoint: `/source-runtimes/health?source_id=legit_security`
- Source health receipt: `sources/legit_security/source_health_receipt.json`
- EvidenceCAS reference kind: `legit_security.evidence_cas_reference`

## Families

- `assets`, emits `legit_security.assets`, reads `/v1/assets`
- `findings`, emits `legit_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `legit_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `legit_security.policies`, reads `/v1/policies`
- `audit_events`, emits `legit_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/legit_security ./internal/sourceprojection -count=1`
- `make catalog-check`
