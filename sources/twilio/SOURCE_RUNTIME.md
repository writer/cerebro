# Twilio

Generated Source Runtime SDK scaffold for `twilio`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/twilio`
- Health endpoint: `/source-runtimes/health?source_id=twilio`
- Source health receipt: `sources/twilio/source_health_receipt.json`
- EvidenceCAS reference kind: `twilio.evidence_cas_reference`

## Families

- `events_json`, emits `twilio.events_json`, reads `/2010-04-01/Accounts/${config.accountsid}/Calls/${config.callsid}/Events.json`
- `accounts_json`, emits `twilio.accounts_json`, reads `/2010-04-01/Accounts.json`
- `credentiallists_json`, emits `twilio.credentiallists_json`, reads `/2010-04-01/Accounts/${config.accountsid}/SIP/CredentialLists.json`
- `ipaccesscontrollists_json`, emits `twilio.ipaccesscontrollists_json`, reads `/2010-04-01/Accounts/${config.accountsid}/SIP/IpAccessControlLists.json`

## Tests

- `go test ./sources/twilio ./internal/sourceprojection -count=1`
- `make catalog-check`
