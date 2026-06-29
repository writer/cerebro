# CrowdStrike Falcon

Generated Source Runtime SDK scaffold for `crowdstrike_falcon`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_client_credentials`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/crowdstrike_falcon`
- Health endpoint: `/source-runtimes/health?source_id=crowdstrike_falcon`
- Source health receipt: `sources/crowdstrike_falcon/source_health_receipt.json`
- EvidenceCAS reference kind: `crowdstrike_falcon.evidence_cas_reference`

## Families

- `endpoint_devices`, emits `crowdstrike_falcon.endpoint_devices`, reads `/v1/devices`
- `findings`, emits `crowdstrike_falcon.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `crowdstrike_falcon.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/crowdstrike_falcon ./internal/sourceprojection -count=1`
- `make catalog-check`
