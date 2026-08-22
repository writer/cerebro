# Compliance Workspace

Use the compliance workspace to review the product with synthetic data. It does not require provider credentials, Docker, or a durable data store.

## Start The Workspace

Prerequisite: Node.js 22 or newer.

```bash
git clone https://github.com/writer/cerebro.git
cd cerebro
make compliance-demo
```

Open `http://127.0.0.1:3000`. The fixture server binds to `127.0.0.1` and starts with a restricted environment.

## Complete The First Review

1. Open **Home** and read the framework readiness score.
2. Open the first item in **Open work queue** and confirm its owner, due date, and current state.
3. Open **Evidence** and filter to missing or stale items.
4. Open **Integrations** and review source freshness and coverage gaps.
5. Open **Audit packets** and review blockers before exporting or sharing a snapshot.

All records in this workspace are synthetic. Fixture behavior proves the browser workflow and route contracts; it does not prove provider access, live collection, deployment, or durable persistence.

## Validate The Browser Contract

```bash
make compliance-demo-check
```

The check starts an isolated fixture server, opens the product routes in Chromium, and fails on route errors, browser errors, or missing page contracts.

## Continue With Real Data

Use [Integration readiness](integration-readiness.md) before selecting a source. Then follow [Getting started](getting-started.md) to run the API and durable stores. Provider configuration belongs outside the credential-free browser workspace.
