# VisibleThread

Generated Source Runtime SDK scaffold for `visiblethread`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/visiblethread`
- Health endpoint: `/source-runtimes/health?source_id=visiblethread`
- Source health receipt: `sources/visiblethread/source_health_receipt.json`
- EvidenceCAS reference kind: `visiblethread.evidence_cas_reference`

## Families

- `webscan`, emits `visiblethread.webscan`, reads `/webscans`
- `document`, emits `visiblethread.document`, reads `/documents`
- `weburl`, emits `visiblethread.weburl`, reads `/webscans/${config.scanid}/webUrls/${config.urlid}`
- `document_2`, emits `visiblethread.document_2`, reads `/documents/${config.docid}`

## Tests

- `go test ./sources/visiblethread ./internal/sourceprojection -count=1`
- `make catalog-check`
