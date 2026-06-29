# Burp Suite Enterprise

Generated Source Runtime SDK scaffold for `burp_suite_enterprise`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/burp_suite_enterprise`
- Health endpoint: `/source-runtimes/health?source_id=burp_suite_enterprise`
- Source health receipt: `sources/burp_suite_enterprise/source_health_receipt.json`
- EvidenceCAS reference kind: `burp_suite_enterprise.evidence_cas_reference`

## Families

- `assets`, emits `burp_suite_enterprise.assets`, reads `/v1/assets`
- `findings`, emits `burp_suite_enterprise.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `burp_suite_enterprise.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `burp_suite_enterprise.policies`, reads `/v1/policies`
- `audit_events`, emits `burp_suite_enterprise.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/burp_suite_enterprise ./internal/sourceprojection -count=1`
- `make catalog-check`
