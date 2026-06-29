# Crowdstrike Identity

Generated Source Runtime SDK scaffold for `crowdstrike_identity`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/crowdstrike_identity`
- Health endpoint: `/source-runtimes/health?source_id=crowdstrike_identity`
- Source health receipt: `sources/crowdstrike_identity/source_health_receipt.json`
- EvidenceCAS reference kind: `crowdstrike_identity.evidence_cas_reference`

## Families

- `assets`, emits `crowdstrike_identity.assets`, reads `/v1/assets`
- `findings`, emits `crowdstrike_identity.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `crowdstrike_identity.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `crowdstrike_identity.policies`, reads `/v1/policies`
- `audit_events`, emits `crowdstrike_identity.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/crowdstrike_identity ./internal/sourceprojection -count=1`
- `make catalog-check`
