# Privacera

Generated Source Runtime SDK scaffold for `privacera`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/privacera`
- Health endpoint: `/source-runtimes/health?source_id=privacera`
- Source health receipt: `sources/privacera/source_health_receipt.json`
- EvidenceCAS reference kind: `privacera.evidence_cas_reference`

## Families

- `assets`, emits `privacera.assets`, reads `/v1/assets`
- `findings`, emits `privacera.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `privacera.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `privacera.policies`, reads `/v1/policies`
- `audit_events`, emits `privacera.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/privacera ./internal/sourceprojection -count=1`
- `make catalog-check`
