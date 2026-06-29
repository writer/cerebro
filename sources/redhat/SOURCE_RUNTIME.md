# Red Hat Patchman

Generated Source Runtime SDK scaffold for `redhat`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/redhat`
- Health endpoint: `/source-runtimes/health?source_id=redhat`
- Source health receipt: `sources/redhat/source_health_receipt.json`
- EvidenceCAS reference kind: `redhat.evidence_cas_reference`

## Families

- `advisory`, emits `redhat.advisory`, reads `/api/patch/v1/export/advisories`
- `package`, emits `redhat.package`, reads `/api/patch/v1/export/packages`
- `systems_advisory`, emits `redhat.systems_advisory`, reads `/api/patch/v1/export/systems/${config.inventory_id}/advisories`
- `v1_package`, emits `redhat.v1_package`, reads `/api/patch/v1/packages/`

## Tests

- `go test ./sources/redhat ./internal/sourceprojection -count=1`
- `make catalog-check`
