# Fastly

Generated Source Runtime SDK scaffold for `fastly`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/fastly`
- Health endpoint: `/source-runtimes/health?source_id=fastly`
- Source health receipt: `sources/fastly/source_health_receipt.json`
- EvidenceCAS reference kind: `fastly.evidence_cas_reference`

## Families

- `services`, emits `fastly.services`, reads `/service`
- `acl_entries`, emits `fastly.acl_entries`, reads `/acl`
- `audit_events`, emits `fastly.audit_events`, reads `/events`

## Tests

- `go test ./sources/fastly ./internal/sourceprojection -count=1`
- `make catalog-check`
