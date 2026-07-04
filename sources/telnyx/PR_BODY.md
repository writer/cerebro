## Summary

- Promotes the `telnyx` Source Runtime contract to provider-verified API proof.
- Maps the existing runtime families to Telnyx API v2 list operations for call events, billing groups, credential connections, managed accounts, call-control applications, notifications, wireless reports, SIM card groups, SIM card group actions, and wireless connectivity logs.
- Refreshes runtime notes and the source-health receipt to match the implemented runtime.

## Runtime contract

- Source type: `json_api`
- Auth model: `bearer_token`
- Auth mechanics: `Authorization: Bearer <API key>`
- Health endpoint: `/source-runtimes/health?source_id=telnyx`
- Base URL: `https://api.telnyx.com/v2`
- Families: `billing_group`, `call_control_application`, `call_event`, `credential_connection`, `detail_records_report`, `managed_account`, `notification_channel`, `notification_event`, `notification_event_condition`, `sim_card_group`, `sim_card_group_action`, `wireless_connectivity_log`
- Deploy manifest: one runtime entry per family, using `TELNYX_TOKEN` as the bearer token and `TELNYX_SIM_CARD_ID` for wireless connectivity logs

## Tests

- `go test ./sources/telnyx ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `make lint-sources catalog-check sourcegen-check check-structural check-structural-test check-arch`
- `make connector-catalog-review connector-api-discovery`

## Review output

- Runtime depth score: `100`
- Fidelity score: `100`
- Provider API proof score: `100`
