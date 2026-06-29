# AbuseIPDB

Generated Source Runtime SDK scaffold for `abuseipdb`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/abuseipdb`
- Health endpoint: `/source-runtimes/health?source_id=abuseipdb`
- Source health receipt: `sources/abuseipdb/source_health_receipt.json`
- EvidenceCAS reference kind: `abuseipdb.evidence_cas_reference`

## Families

- `reports`, emits `abuseipdb.reports`, reads `/reports`
- `ip_addresses`, emits `abuseipdb.ip_addresses`, reads `/ip-addresses`
- `audit_events`, emits `abuseipdb.audit_events`, reads `/audit-events`

## Tests

- `go test ./sources/abuseipdb ./internal/sourceprojection -count=1`
- `make catalog-check`
