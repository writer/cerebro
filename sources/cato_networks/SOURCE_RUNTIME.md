# Cato Networks

Generated Source Runtime SDK scaffold for `cato_networks`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cato_networks`
- Health endpoint: `/source-runtimes/health?source_id=cato_networks`
- Source health receipt: `sources/cato_networks/source_health_receipt.json`
- EvidenceCAS reference kind: `cato_networks.evidence_cas_reference`

## Families

- `assets`, emits `cato_networks.assets`, reads `/v1/assets`
- `findings`, emits `cato_networks.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `cato_networks.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `cato_networks.policies`, reads `/v1/policies`
- `audit_events`, emits `cato_networks.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cato_networks ./internal/sourceprojection -count=1`
- `make catalog-check`
