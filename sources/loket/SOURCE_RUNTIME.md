# Loket

Generated Source Runtime SDK scaffold for `loket`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/loket`
- Health endpoint: `/source-runtimes/health?source_id=loket`
- Source health receipt: `sources/loket/source_health_receipt.json`
- EvidenceCAS reference kind: `loket.evidence_cas_reference`

## Families

- `integration`, emits `loket.integration`, reads `/users/integrations`
- `actualorganizationalentity`, emits `loket.actualorganizationalentity`, reads `/providers/employers/${config.employerid}/actualorganizationalentities`
- `emailidentity`, emits `loket.emailidentity`, reads `/providers/employers/${config.employerid}/emailidentities`
- `customnotification`, emits `loket.customnotification`, reads `/providers/employers/employees/employments/${config.employmentid}/customnotifications`

## Tests

- `go test ./sources/loket ./internal/sourceprojection -count=1`
- `make catalog-check`
