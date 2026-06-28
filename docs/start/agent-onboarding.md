# Agent Onboarding

Use this when someone wants to give a coding agent compliance superpowers with Cerebro.

The flow starts with live source preview over MCP, then upgrades to durable evidence and graph context when you want receipts.

The first answer does not need durable stores. Start Cerebro, add the MCP server to your agent, and have the agent call `cerebro.sources.read`:

```bash
make serve-dev
droid mcp add cerebro-local http://127.0.0.1:8080/api/v1/mcp --type http \
  --header "Authorization: Bearer local-dev-key"
```

For a real durable receipt, set a GitHub repo and token, then run:

```bash
export GITHUB_OWNER=<owner>
export GITHUB_REPO=<repo>
export GITHUB_TOKEN=<token>
make github-business-demo
```

Receipt:

```text
tmp/onboarding/github-receipt.json
```

The receipt answers the first operator questions:

- Is Cerebro running?
- Is auth configured?
- Are Postgres, NATS, and Neo4j reachable?
- Can Cerebro preview live source data?
- Can Cerebro create a GitHub source runtime?
- Can Cerebro sync real source events?
- Can Cerebro run graph ingest?
- Can Cerebro check a compliance profile?
- Which secrets and next actions are still needed?

## Copy This Prompt

```text
I want to use Cerebro as compliance context for my coding agent.

Start with live MCP preview:
make serve-dev
droid mcp add cerebro-local http://127.0.0.1:8080/api/v1/mcp --type http --header "Authorization: Bearer local-dev-key"

Use cerebro.sources.read with source_id=github and config {"owner":"<owner>","repo":"<repo>","per_page":"5"}.

If I need durable graph evidence, run:
GITHUB_OWNER=<owner> GITHUB_REPO=<repo> make github-business-demo
Assume GITHUB_TOKEN is already set in the shell.

Then read tmp/onboarding/github-receipt.json.

Tell me:
- receipt status
- whether this Cerebro setup has live source evidence and durable graph context
- source runtime ids
- available compliance evidence and control coverage
- failed checks, if any
- required secret names
- next actions before I connect real business systems or ask the agent to review a real PR

Do not commit provider credentials, customer names, tenant-specific hostnames, account IDs, or live secret values.
Use env: references for every secret-bearing value.
```

## What The First Runs Do

The MCP preview path uses the source service directly. It can list, check, discover, and read live sources with `cerebro.sources.list`, `cerebro.sources.check`, `cerebro.sources.discover`, and `cerebro.sources.read` before durable stores exist.

The local plan uses the SDK source, local Docker services, and the bearer key from `docker-compose.yml`.

```bash
make secure-business-demo
```

The target starts the local stack from the current checkout, builds `./bin/cerebro`, waits for `/health`, runs `deploy preflight`, creates `local-sdk-demo`, writes sample SDK claims, runs sync and graph ingest checks, checks control coverage, and writes:

```text
tmp/onboarding/e2e-receipt.json
```

The GitHub plan uses live repo data instead of synthetic claims:

```bash
export GITHUB_OWNER=<owner>
export GITHUB_REPO=<repo>
export GITHUB_TOKEN=<token>
make github-business-demo
```

It writes:

```text
tmp/onboarding/github-receipt.json
```

Use `make agent-onboard-e2e` when you want the same run under the workflow name used by CI and docs.

## Run Against An Existing Service

Set the service and backing-store environment used by `deploy preflight`:

```bash
export CEREBRO_API_KEY='<api-key>'
export CEREBRO_API_KEYS='<api-key>:<principal>:<tenant-id>'
export CEREBRO_JETSTREAM_URL='<nats-url>'
export CEREBRO_POSTGRES_DSN='<postgres-dsn>'
export CEREBRO_NEO4J_URI='<neo4j-uri>'
export CEREBRO_NEO4J_USERNAME='<neo4j-user>'
export CEREBRO_NEO4J_PASSWORD='<neo4j-password>'

make agent-onboard PLAN=examples/onboarding/cerebro-onboarding.yaml
```

Override the service URL and receipt path when needed:

```bash
make agent-onboard \
  PLAN=examples/onboarding/cerebro-onboarding.yaml \
  CEREBRO_ONBOARD_BASE_URL=https://cerebro.example.com \
  AGENT_ONBOARD_RECEIPT=tmp/onboarding/hosted-receipt.json
```

## Intake File

The sample intake lives at `examples/onboarding/cerebro-onboarding.yaml`. It is JSON-compatible YAML so the runner can parse it with Python's standard library when PyYAML is not installed.

Plan sections:

| Field | Use |
| --- | --- |
| `tenant_id` | Tenant used for runtime writes and coverage checks. |
| `base_url` | Cerebro HTTP origin. |
| `api_key_env` | Environment variable that holds the API key. |
| `environment` | Values used for `cerebro deploy preflight`; secret-shaped entries must use `env:`. |
| `source_runtimes` | Runtime ids, source ids, config, sample claims, sync, and graph ingest settings. |
| `compliance.profiles` | Control profiles to check after runtime setup. |
| `acceptance_gates` | Operator expectations recorded with the plan. |

Use the local sample as the first business checklist:

| Plan value | First business decision |
| --- | --- |
| `tenant_id` | Pick the tenant or workspace name used in Cerebro records. |
| `source_runtimes[].id` | Name the business system Cerebro should track. |
| `config.integration` | Name the integration family, such as `jira`, `github`, or `okta`. |
| `config.inventory_urns` | List the services, queues, repos, or apps that need ownership and posture checks. |
| `claims` | Start with ownership, SSO, MFA, backup, or vendor-review claims that the team already understands. |
| `compliance.profiles` | Pick the control set the business needs to show first. |

## Receipt

The receipt records:

- preflight result,
- required environment variables,
- enabled capabilities and backing services,
- source preview results,
- runtime write, claim, sync, health, and graph ingest checks,
- compliance coverage checks,
- next actions.

The receipt redacts secret-shaped keys and URL credentials. It should be stored with deployment records, not used as a secret store.

If the receipt fails, fix the first failed check and rerun the same command. Do not add provider credentials until the local receipt passes.

## Checks For This Workflow

```bash
python3 -m unittest scripts.tests.test_agent_onboard
make agent-onboard PLAN=examples/onboarding/cerebro-onboarding.yaml
make agent-onboard-e2e
make secure-business-demo
make github-business-demo
```
