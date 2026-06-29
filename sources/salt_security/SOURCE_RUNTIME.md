# Salt Security

Generated Source Runtime SDK scaffold for `salt_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/salt_security`
- Health endpoint: `/source-runtimes/health?source_id=salt_security`
- Source health receipt: `sources/salt_security/source_health_receipt.json`
- EvidenceCAS reference kind: `salt_security.evidence_cas_reference`

## Families

- `assets`, emits `salt_security.assets`, reads `/v1/assets`
- `findings`, emits `salt_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `salt_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `salt_security.policies`, reads `/v1/policies`
- `audit_events`, emits `salt_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/salt_security ./internal/sourceprojection -count=1`
- `make catalog-check`
