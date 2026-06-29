# Prisma Cloud

Generated Source Runtime SDK scaffold for `prisma_cloud`.

## Runtime input

- Source type: `json_api`
- Auth model: `jwt`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/prisma_cloud`
- Health endpoint: `/source-runtimes/health?source_id=prisma_cloud`
- Source health receipt: `sources/prisma_cloud/source_health_receipt.json`
- EvidenceCAS reference kind: `prisma_cloud.evidence_cas_reference`

## Families

- `assets`, emits `prisma_cloud.assets`, reads `/v1/assets`
- `findings`, emits `prisma_cloud.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `prisma_cloud.vulnerabilities`, reads `/v1/vulnerabilities`

## Tests

- `go test ./sources/prisma_cloud ./internal/sourceprojection -count=1`
- `make catalog-check`
