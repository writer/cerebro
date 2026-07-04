# Telnyx

Source Runtime adapter for Telnyx communications, billing, managed account, notification, and wireless inventory.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Auth mechanics: `Authorization: Bearer <API key>`
- Base URL: `https://api.telnyx.com/v2`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/telnyx`
- Health endpoint: `/source-runtimes/health?source_id=telnyx`
- Source health receipt: `sources/telnyx/source_health_receipt.json`
- Emits call events, billing groups, credential connections, managed accounts, call-control applications, notification configuration, wireless detail-record reports, SIM card groups, SIM card group actions, and wireless connectivity logs.

## Families

- `call_event`, emits `telnyx.call_event`, reads `/call_events`
- `billing_group`, emits `telnyx.billing_group`, reads `/billing_groups`
- `credential_connection`, emits `telnyx.credential_connection`, reads `/credential_connections`
- `managed_account`, emits `telnyx.managed_account`, reads `/managed_accounts`
- `call_control_application`, emits `telnyx.call_control_application`, reads `/call_control_applications`
- `notification_channel`, emits `telnyx.notification_channel`, reads `/notification_channels`
- `detail_records_report`, emits `telnyx.detail_records_report`, reads `/wireless/detail_records_reports`
- `notification_event`, emits `telnyx.notification_event`, reads `/notification_events`
- `notification_event_condition`, emits `telnyx.notification_event_condition`, reads `/notification_event_conditions`
- `wireless_connectivity_log`, emits `telnyx.wireless_connectivity_log`, reads `/sim_cards/${config.sim_card_id}/wireless_connectivity_logs`
- `sim_card_group`, emits `telnyx.sim_card_group`, reads `/sim_card_groups`
- `sim_card_group_action`, emits `telnyx.sim_card_group_action`, reads `/sim_card_group_actions`

## Tests

- `go test ./sources/telnyx ./internal/sourceprojection ./sources/internal/catalogruntime ./internal/connectordefinitions ./internal/connectorcatalog -count=1`
- `make lint-sources catalog-check sourcegen-check check-structural check-structural-test check-arch`
- `make connector-catalog-review connector-api-discovery`
