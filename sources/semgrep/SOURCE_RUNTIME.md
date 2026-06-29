# Semgrep

Generated Source Runtime SDK scaffold for `semgrep`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/semgrep`
- Health endpoint: `/source-runtimes/health?source_id=semgrep`
- Source health receipt: `sources/semgrep/source_health_receipt.json`
- EvidenceCAS reference kind: `semgrep.evidence_cas_reference`

## Families

- `assets`, emits `semgrep.assets`, reads `/v1/assets`
- `findings`, emits `semgrep.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `semgrep.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `semgrep.policies`, reads `/v1/policies`
- `audit_events`, emits `semgrep.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/semgrep ./internal/sourceprojection -count=1`
- `make catalog-check`
