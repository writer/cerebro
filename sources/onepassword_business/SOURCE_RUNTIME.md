# 1Password Business

Generated Source Runtime SDK scaffold for `onepassword_business`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/onepassword_business`
- Health endpoint: `/source-runtimes/health?source_id=onepassword_business`
- Source health receipt: `sources/onepassword_business/source_health_receipt.json`
- EvidenceCAS reference kind: `onepassword_business.evidence_cas_reference`

## Families

- `users`, emits `onepassword_business.users`, reads `/v1/users`
- `secrets`, emits `onepassword_business.secrets`, reads `/v1/secrets`
- `audit_events`, emits `onepassword_business.audit_events`, reads `/v1/audit/events`

## Tests

- `go test ./sources/onepassword_business ./internal/sourceprojection -count=1`
- `make catalog-check`
