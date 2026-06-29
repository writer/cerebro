# Anomali Threatstream

Generated Source Runtime SDK scaffold for `anomali_threatstream`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/anomali_threatstream`
- Health endpoint: `/source-runtimes/health?source_id=anomali_threatstream`
- Source health receipt: `sources/anomali_threatstream/source_health_receipt.json`
- EvidenceCAS reference kind: `anomali_threatstream.evidence_cas_reference`

## Families

- `assets`, emits `anomali_threatstream.assets`, reads `/v1/assets`
- `findings`, emits `anomali_threatstream.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `anomali_threatstream.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `anomali_threatstream.policies`, reads `/v1/policies`
- `audit_events`, emits `anomali_threatstream.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/anomali_threatstream ./internal/sourceprojection -count=1`
- `make catalog-check`
