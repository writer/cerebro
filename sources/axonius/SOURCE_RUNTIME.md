# Axonius

Generated Source Runtime SDK scaffold for `axonius`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/axonius`
- Health endpoint: `/source-runtimes/health?source_id=axonius`
- Source health receipt: `sources/axonius/source_health_receipt.json`
- EvidenceCAS reference kind: `axonius.evidence_cas_reference`

## Families

- `assets`, emits `axonius.assets`, reads `/v1/assets`
- `findings`, emits `axonius.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `axonius.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `axonius.policies`, reads `/v1/policies`
- `audit_events`, emits `axonius.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/axonius ./internal/sourceprojection -count=1`
- `make catalog-check`
