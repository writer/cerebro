# Eclypsium

Generated Source Runtime SDK scaffold for `eclypsium`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/eclypsium`
- Health endpoint: `/source-runtimes/health?source_id=eclypsium`
- Source health receipt: `sources/eclypsium/source_health_receipt.json`
- EvidenceCAS reference kind: `eclypsium.evidence_cas_reference`

## Families

- `assets`, emits `eclypsium.assets`, reads `/v1/assets`
- `findings`, emits `eclypsium.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `eclypsium.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `eclypsium.policies`, reads `/v1/policies`
- `audit_events`, emits `eclypsium.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/eclypsium ./internal/sourceprojection -count=1`
- `make catalog-check`
