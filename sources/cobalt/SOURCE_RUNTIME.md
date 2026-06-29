# Cobalt

Generated Source Runtime SDK scaffold for `cobalt`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cobalt`
- Health endpoint: `/source-runtimes/health?source_id=cobalt`
- Source health receipt: `sources/cobalt/source_health_receipt.json`
- EvidenceCAS reference kind: `cobalt.evidence_cas_reference`

## Families

- `assets`, emits `cobalt.assets`, reads `/v1/assets`
- `findings`, emits `cobalt.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `cobalt.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `cobalt.policies`, reads `/v1/policies`
- `audit_events`, emits `cobalt.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cobalt ./internal/sourceprojection -count=1`
- `make catalog-check`
