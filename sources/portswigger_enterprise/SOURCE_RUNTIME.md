# Portswigger Enterprise

Generated Source Runtime SDK scaffold for `portswigger_enterprise`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/portswigger_enterprise`
- Health endpoint: `/source-runtimes/health?source_id=portswigger_enterprise`
- Source health receipt: `sources/portswigger_enterprise/source_health_receipt.json`
- EvidenceCAS reference kind: `portswigger_enterprise.evidence_cas_reference`

## Families

- `assets`, emits `portswigger_enterprise.assets`, reads `/v1/assets`
- `findings`, emits `portswigger_enterprise.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `portswigger_enterprise.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `portswigger_enterprise.policies`, reads `/v1/policies`
- `audit_events`, emits `portswigger_enterprise.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/portswigger_enterprise ./internal/sourceprojection -count=1`
- `make catalog-check`
