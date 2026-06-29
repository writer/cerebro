# Cisco Umbrella

Generated Source Runtime SDK scaffold for `cisco_umbrella`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cisco_umbrella`
- Health endpoint: `/source-runtimes/health?source_id=cisco_umbrella`
- Source health receipt: `sources/cisco_umbrella/source_health_receipt.json`
- EvidenceCAS reference kind: `cisco_umbrella.evidence_cas_reference`

## Families

- `assets`, emits `cisco_umbrella.assets`, reads `/v1/assets`
- `findings`, emits `cisco_umbrella.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `cisco_umbrella.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `cisco_umbrella.policies`, reads `/v1/policies`
- `audit_events`, emits `cisco_umbrella.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/cisco_umbrella ./internal/sourceprojection -count=1`
- `make catalog-check`
