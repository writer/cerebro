# Ibm Randori

Generated Source Runtime SDK scaffold for `ibm_randori`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/ibm_randori`
- Health endpoint: `/source-runtimes/health?source_id=ibm_randori`
- Source health receipt: `sources/ibm_randori/source_health_receipt.json`
- EvidenceCAS reference kind: `ibm_randori.evidence_cas_reference`

## Families

- `assets`, emits `ibm_randori.assets`, reads `/v1/assets`
- `findings`, emits `ibm_randori.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `ibm_randori.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `ibm_randori.policies`, reads `/v1/policies`
- `audit_events`, emits `ibm_randori.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/ibm_randori ./internal/sourceprojection -count=1`
- `make catalog-check`
