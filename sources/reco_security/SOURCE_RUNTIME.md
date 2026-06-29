# Reco Security

Generated Source Runtime SDK scaffold for `reco_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/reco_security`
- Health endpoint: `/source-runtimes/health?source_id=reco_security`
- Source health receipt: `sources/reco_security/source_health_receipt.json`
- EvidenceCAS reference kind: `reco_security.evidence_cas_reference`

## Families

- `assets`, emits `reco_security.assets`, reads `/v1/assets`
- `findings`, emits `reco_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `reco_security.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `reco_security.policies`, reads `/v1/policies`
- `audit_events`, emits `reco_security.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/reco_security ./internal/sourceprojection -count=1`
- `make catalog-check`
