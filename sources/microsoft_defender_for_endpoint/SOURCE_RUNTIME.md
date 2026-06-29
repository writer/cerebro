# Microsoft Defender for Endpoint

Generated Source Runtime SDK scaffold for `microsoft_defender_for_endpoint`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/microsoft_defender_for_endpoint`
- Health endpoint: `/source-runtimes/health?source_id=microsoft_defender_for_endpoint`
- Source health receipt: `sources/microsoft_defender_for_endpoint/source_health_receipt.json`
- EvidenceCAS reference kind: `microsoft_defender_for_endpoint.evidence_cas_reference`

## Families

- `endpoint_devices`, emits `microsoft_defender_for_endpoint.endpoint_devices`, reads `/v1/devices`
- `findings`, emits `microsoft_defender_for_endpoint.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `microsoft_defender_for_endpoint.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/microsoft_defender_for_endpoint ./internal/sourceprojection -count=1`
- `make catalog-check`
