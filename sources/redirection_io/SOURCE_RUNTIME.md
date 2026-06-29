# redirection.io

Generated Source Runtime SDK scaffold for `redirection_io`.

## Runtime input

- Source type: `json_api`
- Auth model: `api_key`
- Freshness expectation: `24h0m0s`
- Failure modes: `api_error,auth_error,rate_limit,schema_drift`

## Runtime output

- Adapter package: `sources/redirection_io`
- Health endpoint: `/source-runtimes/health?source_id=redirection_io`
- Source health receipt: `sources/redirection_io/source_health_receipt.json`
- EvidenceCAS reference kind: `redirection_io.evidence_cas_reference`

## Families

- `aggregate_log`, emits `redirection_io.aggregate_log`, reads `/aggregate-logs`
- `user`, emits `redirection_io.user`, reads `/users`
- `agent_rule`, emits `redirection_io.agent_rule`, reads `/agent-rules`
- `notification`, emits `redirection_io.notification`, reads `/notifications`
- `smart_list`, emits `redirection_io.smart_list`, reads `/smart-lists`
- `log`, emits `redirection_io.log`, reads `/logs`
- `agent_rule_complexe`, emits `redirection_io.agent_rule_complexe`, reads `/agent-rule-complexes`
- `agent_rule_straight`, emits `redirection_io.agent_rule_straight`, reads `/agent-rule-straights`
- `export_rule`, emits `redirection_io.export_rule`, reads `/export-rules`
- `rule`, emits `redirection_io.rule`, reads `/rules`
- `rule_change`, emits `redirection_io.rule_change`, reads `/rule-changes`
- `rule_set_version`, emits `redirection_io.rule_set_version`, reads `/rule-set-versions`

## Tests

- `go test ./sources/redirection_io ./internal/sourceprojection -count=1`
- `make catalog-check`
