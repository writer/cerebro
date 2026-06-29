# Noname Security

Generated Source Runtime SDK scaffold for `noname_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/noname_security`
- Health endpoint: `/source-runtimes/health?source_id=noname_security`
- Source health receipt: `sources/noname_security/source_health_receipt.json`
- EvidenceCAS reference kind: `noname_security.evidence_cas_reference`

## Families

- `assets`, emits `noname_security.assets`, reads `/v1/assets`
- `findings`, emits `noname_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `noname_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `noname_security.policies`, reads `/v1/policies`
- `audit_events`, emits `noname_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/noname_security ./internal/sourceprojection -count=1`
- `make catalog-check`
