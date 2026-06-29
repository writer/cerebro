# Normalyze

Generated Source Runtime SDK scaffold for `normalyze`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/normalyze`
- Health endpoint: `/source-runtimes/health?source_id=normalyze`
- Source health receipt: `sources/normalyze/source_health_receipt.json`
- EvidenceCAS reference kind: `normalyze.evidence_cas_reference`

## Families

- `assets`, emits `normalyze.assets`, reads `/v1/assets`
- `findings`, emits `normalyze.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `normalyze.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `normalyze.policies`, reads `/v1/policies`
- `audit_events`, emits `normalyze.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/normalyze ./internal/sourceprojection -count=1`
- `make catalog-check`
