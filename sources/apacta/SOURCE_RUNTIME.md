# Apacta

Generated Source Runtime SDK scaffold for `apacta`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/apacta`
- Health endpoint: `/source-runtimes/health?source_id=apacta`
- Source health receipt: `sources/apacta/source_health_receipt.json`
- EvidenceCAS reference kind: `apacta.evidence_cas_reference`

## Families

- `activity`, emits `apacta.activity`, reads `/activities`
- `mass_messages_user`, emits `apacta.mass_messages_user`, reads `/mass_messages_users`
- `role`, emits `apacta.role`, reads `/roles`
- `city`, emits `apacta.city`, reads `/cities`
- `event`, emits `apacta.event`, reads `/events`
- `changelog`, emits `apacta.changelog`, reads `/offers/${config.offer_id}/changelog`
- `time_entry_rule_group`, emits `apacta.time_entry_rule_group`, reads `/time_entry_rule_groups`
- `user`, emits `apacta.user`, reads `/users`
- `user_custom_field_attribute`, emits `apacta.user_custom_field_attribute`, reads `/user_custom_field_attributes`
- `contact_person`, emits `apacta.contact_person`, reads `/contacts/${config.contact_id}/contact_persons`
- `projects_user`, emits `apacta.projects_user`, reads `/projects/${config.project_id}/users/`
- `user_custom_field_value`, emits `apacta.user_custom_field_value`, reads `/users/${config.user_id}/user_custom_field_value`

## Tests

- `go test ./sources/apacta ./internal/sourceprojection -count=1`
- `make catalog-check`
