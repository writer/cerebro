# Trufflehog Enterprise

Generated Source Runtime SDK scaffold for `trufflehog_enterprise`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/trufflehog_enterprise`
- Health endpoint: `/source-runtimes/health?source_id=trufflehog_enterprise`
- Source health receipt: `sources/trufflehog_enterprise/source_health_receipt.json`
- EvidenceCAS reference kind: `trufflehog_enterprise.evidence_cas_reference`

## Families

- `assets`, emits `trufflehog_enterprise.assets`, reads `/v1/assets`
- `findings`, emits `trufflehog_enterprise.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `trufflehog_enterprise.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `trufflehog_enterprise.policies`, reads `/v1/policies`
- `audit_events`, emits `trufflehog_enterprise.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/trufflehog_enterprise ./internal/sourceprojection -count=1`
- `make catalog-check`
