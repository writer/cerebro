# Snyk

Source Runtime SDK adapter for `snyk`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/snyk`
- Health endpoint: `/source-runtimes/health?source_id=snyk`
- Source health receipt: `sources/snyk/source_health_receipt.json`
- EvidenceCAS reference kind: `snyk.evidence_cas_reference`

## Families

- `orgs`, emits `snyk.orgs`, reads `/orgs`
- `groups`, emits `snyk.groups`, reads `/groups`
- `projects`, emits `snyk.projects`, reads `/orgs/{org_id}/projects`
- `targets`, emits `snyk.targets`, reads `/orgs/{org_id}/targets`
- `assets`, emits `snyk.assets`, reads `/orgs/{org_id}/inventory/assets`
- `findings`, emits `snyk.findings`, reads `/orgs/{org_id}/issues`
- `vulnerabilities`, emits `snyk.vulnerabilities`, reads `/orgs/{org_id}/issues?type=package_vulnerability`

## Tests

- `go test ./sources/snyk ./internal/sourceprojection -count=1`
- `make catalog-check`
