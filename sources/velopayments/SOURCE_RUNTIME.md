# Velo Payments

Generated Source Runtime SDK scaffold for `velopayments`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/velopayments`
- Health endpoint: `/source-runtimes/health?source_id=velopayments`
- Source health receipt: `sources/velopayments/source_health_receipt.json`
- EvidenceCAS reference kind: `velopayments.evidence_cas_reference`

## Families

- `delta`, emits `velopayments.delta`, reads `/v4/payments/deltas`
- `sourceaccount`, emits `velopayments.sourceaccount`, reads `/v3/sourceAccounts`
- `paymentchannelrule`, emits `velopayments.paymentchannelrule`, reads `/v1/paymentChannelRules`
- `webhook`, emits `velopayments.webhook`, reads `/v1/webhooks`

## Tests

- `go test ./sources/velopayments ./internal/sourceprojection -count=1`
- `make catalog-check`
