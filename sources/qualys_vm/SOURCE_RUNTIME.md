# Qualys VM

Generated Source Runtime SDK scaffold for `qualys_vm`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/qualys_vm`
- Health endpoint: `/source-runtimes/health?source_id=qualys_vm`
- Source health receipt: `sources/qualys_vm/source_health_receipt.json`
- EvidenceCAS reference kind: `qualys_vm.evidence_cas_reference`

## Families

- `assets`, emits `qualys_vm.assets`, reads `/v1/assets`
- `findings`, emits `qualys_vm.findings`, reads `/v1/findings`
- `vulnerabilities`, emits `qualys_vm.vulnerabilities`, reads `/v1/vulnerabilities`
- `policies`, emits `qualys_vm.policies`, reads `/v1/policies`
- `audit_events`, emits `qualys_vm.audit_events`, reads `/v1/audit_events`

## Tests

- `go test ./sources/qualys_vm ./internal/sourceprojection -count=1`
- `make catalog-check`
