# Sonatype Lifecycle

Generated Source Runtime SDK scaffold for `sonatype_lifecycle`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sonatype_lifecycle`
- Health endpoint: `/source-runtimes/health?source_id=sonatype_lifecycle`
- Source health receipt: `sources/sonatype_lifecycle/source_health_receipt.json`
- EvidenceCAS reference kind: `sonatype_lifecycle.evidence_cas_reference`

## Families

- `assets`, emits `sonatype_lifecycle.assets`, reads `/v1/assets`
- `findings`, emits `sonatype_lifecycle.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `sonatype_lifecycle.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `sonatype_lifecycle.policies`, reads `/v1/policies`
- `audit_events`, emits `sonatype_lifecycle.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/sonatype_lifecycle ./internal/sourceprojection -count=1`
- `make catalog-check`
