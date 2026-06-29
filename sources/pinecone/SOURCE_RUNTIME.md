# Pinecone

Generated Source Runtime SDK scaffold for `pinecone`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/pinecone`
- Health endpoint: `/source-runtimes/health?source_id=pinecone`
- Source health receipt: `sources/pinecone/source_health_receipt.json`
- EvidenceCAS reference kind: `pinecone.evidence_cas_reference`

## Families

- `indexes`, emits `pinecone.indexes`, reads `/indexes`
- `collections`, emits `pinecone.collections`, reads `/collections`
- `backups`, emits `pinecone.backups`, reads `/backups`
- `restore_jobs`, emits `pinecone.restore_jobs`, reads `/restore-jobs`

## Tests

- `go test ./sources/pinecone ./internal/sourceprojection -count=1`
- `make catalog-check`
