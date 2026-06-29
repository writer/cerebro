# Aqua Security

Generated Source Runtime SDK scaffold for `aqua_security`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/aqua_security`
- Health endpoint: `/source-runtimes/health?source_id=aqua_security`
- Source health receipt: `sources/aqua_security/source_health_receipt.json`
- EvidenceCAS reference kind: `aqua_security.evidence_cas_reference`

## Families

- `assets`, emits `aqua_security.assets`, reads `/v1/assets`
- `findings`, emits `aqua_security.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `aqua_security.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/aqua_security ./internal/sourceprojection -count=1`
- `make catalog-check`
