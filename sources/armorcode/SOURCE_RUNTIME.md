# Armorcode

Generated Source Runtime SDK scaffold for `armorcode`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/armorcode`
- Health endpoint: `/source-runtimes/health?source_id=armorcode`
- Source health receipt: `sources/armorcode/source_health_receipt.json`
- EvidenceCAS reference kind: `armorcode.evidence_cas_reference`

## Families

- `assets`, emits `armorcode.assets`, reads `/v1/assets`
- `findings`, emits `armorcode.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `armorcode.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `armorcode.policies`, reads `/v1/policies`
- `audit_events`, emits `armorcode.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/armorcode ./internal/sourceprojection -count=1`
- `make catalog-check`
