# Dragos Worldview

Generated Source Runtime SDK scaffold for `dragos_worldview`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/dragos_worldview`
- Health endpoint: `/source-runtimes/health?source_id=dragos_worldview`
- Source health receipt: `sources/dragos_worldview/source_health_receipt.json`
- EvidenceCAS reference kind: `dragos_worldview.evidence_cas_reference`

## Families

- `assets`, emits `dragos_worldview.assets`, reads `/v1/assets`
- `findings`, emits `dragos_worldview.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `dragos_worldview.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `dragos_worldview.policies`, reads `/v1/policies`
- `audit_events`, emits `dragos_worldview.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/dragos_worldview ./internal/sourceprojection -count=1`
- `make catalog-check`
