# Getting Started

This guide walks through the fastest live-source preview, then a local durable Cerebro run. The live preview gives an agent real provider context before Postgres, NATS, or Neo4j are configured.

## Get A Live Answer First

Start the lightweight server:

```bash
make serve-dev
```

In another shell, read one page from a public GitHub repo:

```bash
./bin/cerebro source read github owner=writer repo=cerebro per_page=5
```

Connect the same server to Droid over MCP:

```bash
droid mcp add cerebro-local http://127.0.0.1:8080/api/v1/mcp --type http \
  --header "Authorization: Bearer local-dev-key"
```

Then ask your agent to call `cerebro.sources.read` with `source_id=github` and `config={"owner":"writer","repo":"cerebro","per_page":"5"}`. That call uses live source preview and does not require durable stores.

## Start The Durable Stack

```bash
docker compose pull
docker compose up -d
```

The stack exposes Cerebro on `http://127.0.0.1:8080` with NATS JetStream, Postgres, Neo4j, and the local bearer key `local-dev-key` configured by the compose file.

Use `docker compose -f docker-compose.yml -f docker-compose.build.yml up --build -d` when you need the durable stack to run the current checkout instead of the published image.

In another shell, check readiness and the source catalog:

```bash
export CEREBRO_API_KEY=local-dev-key
curl -sS http://127.0.0.1:8080/health
curl -sS --oauth2-bearer "$CEREBRO_API_KEY" http://127.0.0.1:8080/sources
```

## Create An SDK Source Runtime

The `sdk` source is the generic push source for application-owned posture or inventory claims.

```bash
curl -sS -X PUT http://127.0.0.1:8080/source-runtimes/local-sdk-demo \
  --oauth2-bearer "$CEREBRO_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{
    "runtime": {
      "id": "local-sdk-demo",
      "source_id": "sdk",
      "tenant_id": "local",
      "config": {
        "integration": "demo",
        "inventory_urns": "urn:cerebro:local:runtime:local-sdk-demo:service:example-api"
      }
    }
  }'
```

`inventory_urns` is optional. It lets `source discover sdk ...` preview declared SDK-owned inventory, while durable posture evidence still flows through runtime claims.

## Write A Synthetic Claim

```bash
curl -sS -X POST http://127.0.0.1:8080/source-runtimes/local-sdk-demo/claims \
  --oauth2-bearer "$CEREBRO_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{
    "claims": [
      {
        "subject_urn": "urn:cerebro:local:runtime:local-sdk-demo:service:example-api",
        "subject_ref": {
          "urn": "urn:cerebro:local:runtime:local-sdk-demo:service:example-api",
          "entity_type": "service",
          "label": "Example API"
        },
        "predicate": "owner",
        "object_value": "platform",
        "claim_type": "attribute",
        "source_event_id": "demo-claim-1"
      }
    ]
  }'
```

Read the claim back:

```bash
curl -sS \
  --oauth2-bearer "$CEREBRO_API_KEY" \
  'http://127.0.0.1:8080/source-runtimes/local-sdk-demo/claims?limit=10'
```

## Try The SDK Helpers

Python:

```bash
cd sdk/python
CEREBRO_BASE_URL=http://127.0.0.1:8080 \
CEREBRO_API_KEY=local-dev-key \
CEREBRO_TENANT_ID=local \
CEREBRO_RUNTIME_ID=local-jira-posture \
python3 examples/jira_posture_onboarding.py
```

TypeScript:

```bash
cd sdk/typescript
npm ci
npm test
npm run typecheck
```

The TypeScript Jira posture example lives at `sdk/typescript/examples/jira_posture_onboarding.ts`. Run it with your preferred TypeScript runner, or use it as reference application code.

## Seed A Real GitHub Repo

Use this when the agent needs durable graph context from your own repo:

```bash
export GITHUB_OWNER=<owner>
export GITHUB_REPO=<repo>
export GITHUB_TOKEN=<token>
make github-business-demo
```

The receipt is written to `tmp/onboarding/github-receipt.json` and records live source preview, runtime sync, graph ingest, and compliance coverage checks.

## Validate Your Change

For README or public docs changes:

```bash
make readme-check
make docs-drift-check
make oss-audit
```

For SDK helper changes:

```bash
make sdk-test
make sdk-dependency-audit
```
