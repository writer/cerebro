# Getting Started

This guide walks through a local, durable Cerebro run and a small SDK-style claim write. It uses the current bootstrap HTTP API and avoids provider credentials.

## Start The Durable Stack

```bash
docker compose up --build
```

The stack exposes Cerebro on `http://127.0.0.1:8080` with NATS JetStream, Postgres, Neo4j, and the local bearer key `local-dev-key` configured by the compose file.

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
