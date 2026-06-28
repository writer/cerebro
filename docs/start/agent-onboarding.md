# Agent Onboarding

This workflow gives a coding agent one plan file, one command, and one receipt. It is for setup, source runtime onboarding, and security/compliance checks against a local or hosted Cerebro service.

Use it when an operator wants an agent to:

- start from a declared intake file,
- avoid committing provider secrets,
- run deployment preflight,
- create source runtimes,
- write and read a sample claim,
- run runtime sync and graph ingest checks,
- check compliance coverage,
- return a redacted setup receipt.

## Copy This Prompt

```text
Set up Cerebro from examples/onboarding/cerebro-onboarding.yaml.

Use make agent-onboard.
Do not put provider credentials, tenant-specific hostnames, account IDs, or live secret values in the repository.
Use env: references for secret-bearing values.
Run the local end-to-end target if Docker is available.
Return the receipt status, failed checks, required secrets, source runtime ids, and next actions.
```

## Local End-To-End Run

The local plan uses the SDK source, local Docker services, and the bearer key from `docker-compose.yml`.

```bash
make agent-onboard-e2e
```

The target starts the local stack, builds `./bin/cerebro`, waits for `/health`, runs `deploy preflight`, creates `local-sdk-demo`, writes sample SDK claims, runs sync and graph ingest checks, checks control coverage, and writes:

```text
tmp/onboarding/e2e-receipt.json
```

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

## Checks For This Workflow

```bash
python3 -m unittest scripts.tests.test_agent_onboard
make agent-onboard PLAN=examples/onboarding/cerebro-onboarding.yaml
make agent-onboard-e2e
```
