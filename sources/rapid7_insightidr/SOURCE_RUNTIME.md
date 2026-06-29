# Rapid7 Insightidr

Generated Source Runtime SDK scaffold for `rapid7_insightidr`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/rapid7_insightidr`
- Health endpoint: `/source-runtimes/health?source_id=rapid7_insightidr`
- Source health receipt: `sources/rapid7_insightidr/source_health_receipt.json`
- EvidenceCAS reference kind: `rapid7_insightidr.evidence_cas_reference`

## Families

- `assets`, emits `rapid7_insightidr.assets`, reads `/v1/assets`
- `findings`, emits `rapid7_insightidr.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `rapid7_insightidr.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `rapid7_insightidr.policies`, reads `/v1/policies`
- `audit_events`, emits `rapid7_insightidr.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/rapid7_insightidr ./internal/sourceprojection -count=1`
- `make catalog-check`
