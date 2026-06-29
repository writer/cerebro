# Obsidian Security

Generated Source Runtime SDK scaffold for `obsidian_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/obsidian_security`
- Health endpoint: `/source-runtimes/health?source_id=obsidian_security`
- Source health receipt: `sources/obsidian_security/source_health_receipt.json`
- EvidenceCAS reference kind: `obsidian_security.evidence_cas_reference`

## Families

- `assets`, emits `obsidian_security.assets`, reads `/v1/assets`
- `findings`, emits `obsidian_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `obsidian_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `obsidian_security.policies`, reads `/v1/policies`
- `audit_events`, emits `obsidian_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/obsidian_security ./internal/sourceprojection -count=1`
- `make catalog-check`
