# MotaWord

Generated Source Runtime SDK scaffold for `motaword`.

## Runtime input

- Source type: `json_api`
- Auth model: `basic`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/motaword`
- Health endpoint: `/source-runtimes/health?source_id=motaword`
- Source health receipt: `sources/motaword/source_health_receipt.json`
- EvidenceCAS reference kind: `motaword.evidence_cas_reference`

## Families

- `comment`, emits `motaword.comment`, reads `/projects/${config.projectid}/comments`
- `user`, emits `motaword.user`, reads `/users`
- `permission`, emits `motaword.permission`, reads `/corporates/${config.corporateid}/permissions`
- `corporates_user`, emits `motaword.corporates_user`, reads `/corporates/${config.corporateid}/users`
- `user_group`, emits `motaword.user_group`, reads `/corporates/${config.corporateid}/user-groups`
- `user_group_2`, emits `motaword.user_group_2`, reads `/${config.userid}/user-groups`
- `blog`, emits `motaword.blog`, reads `/blogs`
- `activity`, emits `motaword.activity`, reads `/projects/${config.id}/sales/activities`
- `projects_activity`, emits `motaword.projects_activity`, reads `/projects/${config.projectid}/activities`
- `activities_comment`, emits `motaword.activities_comment`, reads `/projects/${config.projectid}/activities/${config.activityid}/comments`
- `corporate_user`, emits `motaword.corporate_user`, reads `/corporate/users`
- `corporate_user_group`, emits `motaword.corporate_user_group`, reads `/corporate/user-groups`

## Tests

- `go test ./sources/motaword ./internal/sourceprojection -count=1`
- `make catalog-check`
