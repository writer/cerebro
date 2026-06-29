# Mimecast

Generated Source Runtime SDK scaffold for `mimecast`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/mimecast`
- Health endpoint: `/source-runtimes/health?source_id=mimecast`
- Source health receipt: `sources/mimecast/source_health_receipt.json`
- EvidenceCAS reference kind: `mimecast.evidence_cas_reference`

## Families

- `assets`, emits `mimecast.assets`, reads `/v1/assets`
- `findings`, emits `mimecast.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `mimecast.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `mimecast.policies`, reads `/v1/policies`
- `audit_events`, emits `mimecast.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/mimecast ./internal/sourceprojection -count=1`
- `make catalog-check`
