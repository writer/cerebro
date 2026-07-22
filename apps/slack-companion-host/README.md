# Cerebro Slack companion host

This workspace contains the executable Slack runtime for Cerebro. It owns Slack event handling, thread context, progress and response delivery, tool registration, host-side policy enforcement, durable outcome handling, and the adapters that connect portable companion contracts to runtime services.

The runtime consumes portable behavior from `@writer/cerebro-slack-companion` and Cerebro API types from `@writer/cerebro-sdk`. Deployment repositories consume this workspace as a pinned public source artifact.

Environment bindings stay outside this workspace. A deployment supplies credentials, destination identifiers, service endpoints, durable storage, cloud resources, rollout policy, and runtime configuration through validated environment bindings.

## Run checks

```bash
npm run check --workspace @writer/cerebro-slack-companion-host
```

## Start the runtime

Build the workspace, provide the documented runtime environment, then run:

```bash
npm start --workspace @writer/cerebro-slack-companion-host
```

The process accepts configured Slack app mentions, preserves bounded thread context, sends governed Cerebro requests, and records durable delivery and outcome state. `/healthz` reports process health. `/readyz` opens after Slack and the outcome store are ready.
