# DocuSign

Generated Source Runtime SDK scaffold for `docusign`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/docusign`
- Health endpoint: `/source-runtimes/health?source_id=docusign`
- Source health receipt: `sources/docusign/source_health_receipt.json`
- EvidenceCAS reference kind: `docusign.evidence_cas_reference`

## Families

- `bcc_email_archive`, emits `docusign.bcc_email_archive`, reads `/v2.1/accounts/${config.accountid}/settings/bcc_email_archives`
- `signing_group`, emits `docusign.signing_group`, reads `/v2.1/accounts/${config.accountid}/signing_groups`
- `request_log`, emits `docusign.request_log`, reads `/v2.1/diagnostics/request_logs`
- `permission_profile`, emits `docusign.permission_profile`, reads `/v2.1/accounts/${config.accountid}/permission_profiles`

## Tests

- `go test ./sources/docusign ./internal/sourceprojection -count=1`
- `make catalog-check`
