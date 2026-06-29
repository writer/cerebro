# Learnifier

Generated Source Runtime SDK scaffold for `learnifier`.

## Runtime input

- Source type: `json_api`
- Auth model: `bearer_token`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/learnifier`
- Health endpoint: `/source-runtimes/health?source_id=learnifier`
- Source health receipt: `sources/learnifier/source_health_receipt.json`
- EvidenceCAS reference kind: `learnifier.evidence_cas_reference`

## Families

- `globalusergroup`, emits `learnifier.globalusergroup`, reads `/globalusergroups`
- `coursedesign`, emits `learnifier.coursedesign`, reads `/coursedesigns`
- `user`, emits `learnifier.user`, reads `/users`
- `member`, emits `learnifier.member`, reads `/globalusergroups/${config.groupid}/members`
- `usergroup`, emits `learnifier.usergroup`, reads `/orgunits/${config.orgid}/usergroups`
- `usergroups_member`, emits `learnifier.usergroups_member`, reads `/orgunits/${config.orgid}/usergroups/${config.groupid}/members`
- `teammember`, emits `learnifier.teammember`, reads `/orgunits/${config.orgid}/projects/${config.projectid}/teammembers`
- `orgunits_usergroup`, emits `learnifier.orgunits_usergroup`, reads `/orgunits/${config.orgid}/usergroups/${config.groupid}`
- `orgunit`, emits `learnifier.orgunit`, reads `/orgunits`
- `project`, emits `learnifier.project`, reads `/orgunits/${config.orgid}/projects`
- `participant`, emits `learnifier.participant`, reads `/orgunits/${config.orgid}/projects/${config.projectid}/participants`

## Tests

- `go test ./sources/learnifier ./internal/sourceprojection -count=1`
- `make catalog-check`
