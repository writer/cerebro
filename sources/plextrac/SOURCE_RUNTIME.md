# Plextrac

Generated Source Runtime SDK scaffold for `plextrac`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/plextrac`
- Health endpoint: `/source-runtimes/health?source_id=plextrac`
- Source health receipt: `sources/plextrac/source_health_receipt.json`
- EvidenceCAS reference kind: `plextrac.evidence_cas_reference`

## Families

- `assets`, emits `plextrac.assets`, reads `/v1/assets`
- `findings`, emits `plextrac.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `plextrac.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `plextrac.policies`, reads `/v1/policies`
- `audit_events`, emits `plextrac.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/plextrac ./internal/sourceprojection -count=1`
- `make catalog-check`
