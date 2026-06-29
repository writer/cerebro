# Netskope

Generated Source Runtime SDK scaffold for `netskope`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/netskope`
- Health endpoint: `/source-runtimes/health?source_id=netskope`
- Source health receipt: `sources/netskope/source_health_receipt.json`
- EvidenceCAS reference kind: `netskope.evidence_cas_reference`

## Families

- `assets`, emits `netskope.assets`, reads `/v1/assets`
- `findings`, emits `netskope.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `netskope.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `netskope.policies`, reads `/v1/policies`
- `audit_events`, emits `netskope.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/netskope ./internal/sourceprojection -count=1`
- `make catalog-check`
