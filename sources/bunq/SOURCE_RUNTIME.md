# bunq

Generated Source Runtime SDK scaffold for `bunq`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/bunq`
- Health endpoint: `/source-runtimes/health?source_id=bunq`
- Source health receipt: `sources/bunq/source_health_receipt.json`
- EvidenceCAS reference kind: `bunq.evidence_cas_reference`

## Families

- `event`, emits `bunq.event`, reads `/user/${config.userid}/event`
- `user`, emits `bunq.user`, reads `/user`
- `credential_password_ip`, emits `bunq.credential_password_ip`, reads `/user/${config.userid}/credential-password-ip`
- `notification_filter_push`, emits `bunq.notification_filter_push`, reads `/user/${config.userid}/notification-filter-push`

## Tests

- `go test ./sources/bunq ./internal/sourceprojection -count=1`
- `make catalog-check`
