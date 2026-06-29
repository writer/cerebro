# Square

Generated Source Runtime SDK scaffold for `square`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/square`
- Health endpoint: `/source-runtimes/health?source_id=square`
- Source health receipt: `sources/square/source_health_receipt.json`
- EvidenceCAS reference kind: `square.evidence_cas_reference`

## Families

- `activity`, emits `square.activity`, reads `/v2/gift-cards/activities`
- `bank_account`, emits `square.bank_account`, reads `/v2/bank-accounts`
- `group`, emits `square.group`, reads `/v2/customers/groups`
- `team_member_booking_profile`, emits `square.team_member_booking_profile`, reads `/v2/bookings/team-member-booking-profiles`

## Tests

- `go test ./sources/square ./internal/sourceprojection -count=1`
- `make catalog-check`
