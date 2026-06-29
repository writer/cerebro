# Arctic Wolf

Generated Source Runtime SDK scaffold for `arctic_wolf`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/arctic_wolf`
- Health endpoint: `/source-runtimes/health?source_id=arctic_wolf`
- Source health receipt: `sources/arctic_wolf/source_health_receipt.json`
- EvidenceCAS reference kind: `arctic_wolf.evidence_cas_reference`

## Families

- `assets`, emits `arctic_wolf.assets`, reads `/v1/assets`
- `findings`, emits `arctic_wolf.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `arctic_wolf.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `arctic_wolf.policies`, reads `/v1/policies`
- `audit_events`, emits `arctic_wolf.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/arctic_wolf ./internal/sourceprojection -count=1`
- `make catalog-check`
