# Sakari

Generated Source Runtime SDK scaffold for `sakari`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/sakari`
- Health endpoint: `/source-runtimes/health?source_id=sakari`
- Source health receipt: `sources/sakari/source_health_receipt.json`
- EvidenceCAS reference kind: `sakari.evidence_cas_reference`

## Families

- `webhook`, emits `sakari.webhook`, reads `/v1/accounts/${config.accountid}/webhooks`
- `campaign`, emits `sakari.campaign`, reads `/v1/accounts/${config.accountid}/campaigns`
- `contact`, emits `sakari.contact`, reads `/v1/accounts/${config.accountid}/contacts`
- `conversation`, emits `sakari.conversation`, reads `/v1/accounts/${config.accountid}/conversations`

## Tests

- `go test ./sources/sakari ./internal/sourceprojection -count=1`
- `make catalog-check`
