# WhatsApp Business

Generated Source Runtime SDK scaffold for `whatsapp`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/whatsapp`
- Health endpoint: `/source-runtimes/health?source_id=whatsapp`
- Source health receipt: `sources/whatsapp/source_health_receipt.json`
- EvidenceCAS reference kind: `whatsapp.evidence_cas_reference`

## Families

- `group`, emits `whatsapp.group`, reads `/groups`
- `user`, emits `whatsapp.user`, reads `/users/${config.userusername}`
- `invite`, emits `whatsapp.invite`, reads `/groups/${config.groupid}/invite`
- `group_2`, emits `whatsapp.group_2`, reads `/groups/${config.groupid}`

## Tests

- `go test ./sources/whatsapp ./internal/sourceprojection -count=1`
- `make catalog-check`
