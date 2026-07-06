# ADP Workforce Now

Provider-verified Source Runtime SDK for `adp_workforce_now`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Auth mechanics: OAuth 2.0 access token sent as `Authorization: Bearer` with ADP's documented client certificate transport authentication for API requests
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/adp_workforce_now`
- Health endpoint: `/source-runtimes/health?source_id=adp_workforce_now`
- Source health receipt: `sources/adp_workforce_now/source_health_receipt.json`
- EvidenceCAS reference kind: `adp_workforce_now.evidence_cas_reference`

## Families

- `event_notifications`, emits `adp_workforce_now.event_notifications`, reads `GET /core/v1/event-notification-messages` from the documented ADP Event Notifications guide as change-event evidence.
- `users`, emits `adp_workforce_now.users`, reads `GET /hr/v2/workers` from the documented ADP Workforce Now Workers API. The health check reads `GET /hr/v2/workers/meta`.

## Tests

- `go test ./sources/adp_workforce_now ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `golangci-lint run -j 4 --timeout 5m ./sources/adp_workforce_now/...`
- `make catalog-check sourcegen-check`
- `make connector-catalog-review`
