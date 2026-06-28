# Agent Onboarding

Use this when someone wants to give a coding agent compliance superpowers with Cerebro.

The flow sets up local Cerebro context, proves the basic security and compliance path works, and returns a receipt the agent can use before it reviews, changes, or ships code.

The first run does not need provider credentials. It starts Cerebro locally, creates a demo runtime, writes two posture claims, checks graph ingest, checks compliance coverage, and saves a receipt.

```bash
make secure-business-demo
```

Receipt:

```text
tmp/onboarding/e2e-receipt.json
```

The receipt answers the first operator questions:

- Is Cerebro running?
- Is auth configured?
- Are Postgres, NATS, and Neo4j reachable?
- Can Cerebro create a source runtime?
- Can Cerebro write and read posture claims?
- Can Cerebro run graph ingest?
- Can Cerebro check a compliance profile?
- Which secrets and next actions are still needed?

## Copy This Prompt

```text
I want to use Cerebro as compliance context for my coding agent.

Start with the local demo:
make secure-business-demo

Then read tmp/onboarding/e2e-receipt.json.

Tell me:
- receipt status
- whether this Cerebro setup is ready to answer ship/no-ship questions
- source runtime ids
- available compliance evidence and control coverage
- failed checks, if any
- required secret names
- next actions before I connect real business systems or ask the agent to review a real PR

Do not commit provider credentials, customer names, tenant-specific hostnames, account IDs, or live secret values.
Use env: references for every secret-bearing value.
```

## What The First Run Does

The local plan uses the SDK source, local Docker services, and the bearer key from `docker-compose.yml`.

```bash
make secure-business-demo
```

The target starts the local stack, builds `./bin/cerebro`, waits for `/health`, runs `deploy preflight`, creates `local-sdk-demo`, writes sample SDK claims, runs sync and graph ingest checks, checks control coverage, and writes:

```text
tmp/onboarding/e2e-receipt.json
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
```
