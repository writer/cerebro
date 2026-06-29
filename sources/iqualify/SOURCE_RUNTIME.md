# iQualify

Generated Source Runtime SDK scaffold for `iqualify`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/iqualify`
- Health endpoint: `/source-runtimes/health?source_id=iqualify`
- Source health receipt: `sources/iqualify/source_health_receipt.json`
- EvidenceCAS reference kind: `iqualify.evidence_cas_reference`

## Families

- `learners_progress`, emits `iqualify.learners_progress`, reads `/offerings/${config.offeringid}/analytics/learners-progress`
- `group`, emits `iqualify.group`, reads `/offerings/${config.offeringid}/groups`
- `user`, emits `iqualify.user`, reads `/offerings/${config.offeringid}/users`
- `pulses`, emits `iqualify.pulses`, reads `/offerings/${config.offeringid}/analytics/pulses`
- `progress`, emits `iqualify.progress`, reads `/users/${config.useremail}/progress`
- `responses`, emits `iqualify.responses`, reads `/offerings/${config.offeringid}/analytics/activities/responses`
- `social_note`, emits `iqualify.social_note`, reads `/offerings/${config.offeringid}/analytics/social-notes`
- `unit_reaction`, emits `iqualify.unit_reaction`, reads `/offerings/${config.offeringid}/analytics/unit-reactions`
- `learner`, emits `iqualify.learner`, reads `/offerings/${config.offeringid}/groups/${config.groupid}/learners`
- `courses`, emits `iqualify.courses`, reads `/courses`
- `current`, emits `iqualify.current`, reads `/offerings/current`
- `future`, emits `iqualify.future`, reads `/offerings/future`

## Tests

- `go test ./sources/iqualify ./internal/sourceprojection -count=1`
- `make catalog-check`
