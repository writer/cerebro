# Torq

Generated Source Runtime SDK scaffold for `torq`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/torq`
- Health endpoint: `/source-runtimes/health?source_id=torq`
- Source health receipt: `sources/torq/source_health_receipt.json`
- EvidenceCAS reference kind: `torq.evidence_cas_reference`

## Families

- `audit_events`, emits `torq.audit_events`, reads `/v1/events`
- `findings`, emits `torq.findings`, reads `/v1/cases`
- `assets`, emits `torq.assets`, reads `/v1/assets`

## Tests

- `go test ./sources/torq ./internal/sourceprojection -count=1`
- `make catalog-check`
