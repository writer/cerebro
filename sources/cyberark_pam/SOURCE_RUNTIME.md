# CyberArk PAM

Generated Source Runtime SDK scaffold for `cyberark_pam`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/cyberark_pam`
- Health endpoint: `/source-runtimes/health?source_id=cyberark_pam`
- Source health receipt: `sources/cyberark_pam/source_health_receipt.json`
- EvidenceCAS reference kind: `cyberark_pam.evidence_cas_reference`

## Families

- `users`, emits `cyberark_pam.users`, reads `/v1/users`
- `secrets`, emits `cyberark_pam.secrets`, reads `/v1/secrets`
- `audit_events`, emits `cyberark_pam.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/cyberark_pam ./internal/sourceprojection -count=1`
- `make catalog-check`
