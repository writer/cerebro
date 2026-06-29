# Noosh

Generated Source Runtime SDK scaffold for `noosh`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/noosh`
- Health endpoint: `/source-runtimes/health?source_id=noosh`
- Source health receipt: `sources/noosh/source_health_receipt.json`
- EvidenceCAS reference kind: `noosh.evidence_cas_reference`

## Families

- `workgroup`, emits `noosh.workgroup`, reads `/v1/workgroups`
- `projecthomeuserfield`, emits `noosh.projecthomeuserfield`, reads `/v1/workgroups/${config.workgroup_id}/projectHomeUserFields`
- `automaticinvitation`, emits `noosh.automaticinvitation`, reads `/v1/workgroups/${config.workgroup_id}/automaticInvitations`
- `clientworkgroup`, emits `noosh.clientworkgroup`, reads `/v1/workgroups/${config.workgroup_id}/clientWorkgroups`
- `supplierworkgroup`, emits `noosh.supplierworkgroup`, reads `/v1/workgroups/${config.workgroup_id}/supplierWorkgroups`
- `teamtemplate`, emits `noosh.teamtemplate`, reads `/v1/workgroups/${config.workgroup_id}/teamTemplates`
- `workgroupmember`, emits `noosh.workgroupmember`, reads `/v1/workgroups/${config.workgroup_id}/workgroupMembers`
- `clientworkgroups_projecthomeuserfield`, emits `noosh.clientworkgroups_projecthomeuserfield`, reads `/v1/workgroups/${config.workgroup_id}/clientWorkgroups/${config.client_workgroup_id}/projectHomeUserFields`
- `teammember`, emits `noosh.teammember`, reads `/v1/workgroups/${config.workgroup_id}/projects/${config.project_id}/teammembers`
- `teammembersofclientproject`, emits `noosh.teammembersofclientproject`, reads `/v1/workgroups/${config.workgroup_id}/projects/${config.project_id}/teamMembersOfClientProject`
- `memberrole`, emits `noosh.memberrole`, reads `/v1/workgroups/${config.workgroup_id}/projects/${config.project_id}/memberroles/${config.user_id}`
- `billingrecipient`, emits `noosh.billingrecipient`, reads `/v1/workgroups/${config.workgroup_id}/billingRecipients`

## Tests

- `go test ./sources/noosh ./internal/sourceprojection -count=1`
- `make catalog-check`
