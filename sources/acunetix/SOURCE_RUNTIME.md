# Acunetix

Generated Source Runtime SDK scaffold for `acunetix`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/acunetix`
- Health endpoint: `/source-runtimes/health?source_id=acunetix`
- Source health receipt: `sources/acunetix/source_health_receipt.json`
- EvidenceCAS reference kind: `acunetix.evidence_cas_reference`

## Families

- `assets`, emits `acunetix.assets`, reads `/v1/assets`
- `findings`, emits `acunetix.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `acunetix.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `acunetix.policies`, reads `/v1/policies`
- `audit_events`, emits `acunetix.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/acunetix ./internal/sourceprojection -count=1`
- `make catalog-check`
