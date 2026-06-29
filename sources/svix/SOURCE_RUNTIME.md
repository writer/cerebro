# Svix

Generated Source Runtime SDK scaffold for `svix`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/svix`
- Health endpoint: `/source-runtimes/health?source_id=svix`
- Source health receipt: `sources/svix/source_health_receipt.json`
- EvidenceCAS reference kind: `svix.evidence_cas_reference`

## Families

- `event_type`, emits `svix.event_type`, reads `/api/v1/event-type/`
- `endpoint`, emits `svix.endpoint`, reads `/api/v1/app/${config.app_id}/endpoint/`
- `msg_endpoint`, emits `svix.msg_endpoint`, reads `/api/v1/app/${config.app_id}/msg/${config.msg_id}/endpoint/`
- `msg`, emits `svix.msg`, reads `/api/v1/app/${config.app_id}/endpoint/${config.endpoint_id}/msg/`

## Tests

- `go test ./sources/svix ./internal/sourceprojection -count=1`
- `make catalog-check`
