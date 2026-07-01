# New Relic

New Relic uses a bespoke NerdGraph source runtime. The runtime posts GraphQL requests to `/graphql` with the `API-Key` header and emits normalized source events for entities, issues, and audit rows.

## Runtime Input

- Source type: `graphql`
- Auth model: `api_key`
- Base URL: `base_url`, default `https://api.newrelic.com`
- Account scope: `account_id` is required for `findings` and `audit_events`
- Asset query: `entity_query`, default `name LIKE '%'`
- Audit query: `audit_nrql`, default `SELECT * FROM NrAuditEvent SINCE 1 day ago LIMIT 100`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Families

- `assets`: `actor.entitySearch(...).results`, emits `new_relic.assets`
- `findings`: `actor.account(id).aiIssues.issues`, emits `new_relic.findings`
- `audit_events`: `actor.account(id).nrql(query: ...)`, emits `new_relic.audit_events`

## Graph Projection

- Assets project as runtime New Relic entity nodes keyed by entity GUID.
- Findings project as finding nodes and link to affected entity GUIDs when the issue payload includes them.
- Audit events project as audit context with actor and resource attributes.

## Tests

- `go test ./sources/new_relic ./internal/sourceprojection -count=1`
- `go run ./tools/catalogcheck`
