# Noetic Cyber

Generated Source Runtime SDK scaffold for `noetic_cyber`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/noetic_cyber`
- Health endpoint: `/source-runtimes/health?source_id=noetic_cyber`
- Source health receipt: `sources/noetic_cyber/source_health_receipt.json`
- EvidenceCAS reference kind: `noetic_cyber.evidence_cas_reference`

## Families

- `assets`, emits `noetic_cyber.assets`, reads `/v1/assets`
- `findings`, emits `noetic_cyber.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `noetic_cyber.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `noetic_cyber.policies`, reads `/v1/policies`
- `audit_events`, emits `noetic_cyber.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/noetic_cyber ./internal/sourceprojection -count=1`
- `make catalog-check`
