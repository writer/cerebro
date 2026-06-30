# ElevenLabs

Source Runtime SDK implementation for `elevenlabs`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/elevenlabs`
- Health endpoint: `/source-runtimes/health?source_id=elevenlabs`
- Source health receipt: `sources/elevenlabs/source_health_receipt.json`
- EvidenceCAS reference kind: `elevenlabs.evidence_cas_reference`

## Families

- `model_catalog`, emits `elevenlabs.model_catalog`, reads `/v1/models`
- `voices`, emits `elevenlabs.voices`, reads `/v2/voices`
- `service_accounts`, emits `elevenlabs.service_accounts`, reads `/v1/service-accounts`
- `service_account_api_keys`, emits `elevenlabs.service_account_api_keys`, reads `/v1/service-accounts/${config.service_account_user_id}/api-keys`
- `webhooks`, emits `elevenlabs.webhooks`, reads `/v1/workspace/webhooks`
- `auth_connections`, emits `elevenlabs.auth_connections`, reads `/v1/workspace/auth-connections`

## Tests

- `go test ./sources/elevenlabs -count=1`
