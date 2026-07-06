# Abnormal Security

Provider-verified Source Runtime SDK for `abnormal_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Auth mechanics: `Authorization: Bearer <token>` header
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/abnormal_security`
- Health endpoint: `/source-runtimes/health?source_id=abnormal_security`
- Source health receipt: `sources/abnormal_security/source_health_receipt.json`
- EvidenceCAS reference kind: `abnormal_security.evidence_cas_reference`

## Families

- `resources`, emits `abnormal_security.resources`, reads `GET /resources`
- `threats`, emits `abnormal_security.threats`, reads `GET /threats`
- `cases`, emits `abnormal_security.cases`, reads `GET /cases`
- `posture_catalog`, emits `abnormal_security.posture_catalog`, reads `GET /spm-v2/posture-catalog`
- `audit_events`, emits `abnormal_security.audit_events`, reads `GET /auditlogs`

## Tests

- `go test ./sources/abnormal_security ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/abnormal_security/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
