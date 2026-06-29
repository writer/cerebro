# AppVeyor

Generated Source Runtime SDK scaffold for `appveyor`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/appveyor`
- Health endpoint: `/source-runtimes/health?source_id=appveyor`
- Source health receipt: `sources/appveyor/source_health_receipt.json`
- EvidenceCAS reference kind: `appveyor.evidence_cas_reference`

## Families

- `role`, emits `appveyor.role`, reads `/roles`
- `user`, emits `appveyor.user`, reads `/users`
- `artifact`, emits `appveyor.artifact`, reads `/buildjobs/${config.jobid}/artifacts`
- `collaborator`, emits `appveyor.collaborator`, reads `/collaborators`

## Tests

- `go test ./sources/appveyor ./internal/sourceprojection -count=1`
- `make catalog-check`
