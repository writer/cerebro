# Datto Autotask PSA

Generated Source Runtime SDK scaffold for `autotask`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/autotask`
- Health endpoint: `/source-runtimes/health?source_id=autotask`
- Source health receipt: `sources/autotask/source_health_receipt.json`
- EvidenceCAS reference kind: `autotask.evidence_cas_reference`

## Families

- `field`, emits `autotask.field`, reads `/V1.0/DeletedTaskActivityLogs/entityInformation/fields`
- `userdefinedfield`, emits `autotask.userdefinedfield`, reads `/V1.0/ActionTypes/entityInformation/userDefinedFields`
- `excludedrole`, emits `autotask.excludedrole`, reads `/V1.0/ContractExclusionSets/${config.parentid}/ExcludedRoles`
- `entityinformation_field`, emits `autotask.entityinformation_field`, reads `/V1.0/CompanyAlerts/entityInformation/fields`

## Tests

- `go test ./sources/autotask ./internal/sourceprojection -count=1`
- `make catalog-check`
