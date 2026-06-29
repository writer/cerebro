# Black Kite

Generated Source Runtime SDK scaffold for `black_kite`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/black_kite`
- Health endpoint: `/source-runtimes/health?source_id=black_kite`
- Source health receipt: `sources/black_kite/source_health_receipt.json`
- EvidenceCAS reference kind: `black_kite.evidence_cas_reference`

## Families

- `assets`, emits `black_kite.assets`, reads `/v1/assets`
- `findings`, emits `black_kite.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `black_kite.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `black_kite.policies`, reads `/v1/policies`
- `audit_events`, emits `black_kite.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/black_kite ./internal/sourceprojection -count=1`
- `make catalog-check`
