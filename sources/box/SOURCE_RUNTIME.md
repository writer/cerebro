# Box

Generated Source Runtime SDK scaffold for `box`.

## Runtime input

- Source type: `json_api`
- Auth model: `oauth_authorization_code`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/box`
- Health endpoint: `/source-runtimes/health?source_id=box`
- Source health receipt: `sources/box/source_health_receipt.json`
- EvidenceCAS reference kind: `box.evidence_cas_reference`

## Families

- `event`, emits `box.event`, reads `/events`
- `group`, emits `box.group`, reads `/groups`
- `shield_information_barrier_segment_member`, emits `box.shield_information_barrier_segment_member`, reads `/shield_information_barrier_segment_members`
- `membership`, emits `box.membership`, reads `/groups/${config.group_id}/memberships`

## Tests

- `go test ./sources/box ./internal/sourceprojection -count=1`
- `make catalog-check`
