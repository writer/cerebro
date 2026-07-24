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

## Archetype workspace

Set `ARCHETYPE_WORKSPACE_ENABLED=true` to replace the static App Home with the
signed-in operator's current Archetype work. The deployment must also provide:

- `ARCHETYPE_BASE_URL`
- `ARCHETYPE_ALLOWED_EMAIL_DOMAINS`
- `OKTA_DOMAIN`
- `OKTA_API_TOKEN`
- optional `ARCHETYPE_REQUEST_TIMEOUT_MS`

The Slack app must enable interactivity and grant `users:read` plus
`users:read.email` so the host can resolve the actor behind a signed Slack
event. Existing mention and App Home scopes remain required.

The runtime reads the Slack user from the verified interaction, requires an
allowed work email, resolves that exact account and its groups from Okta, and
then sends the verified identity to the internal Archetype service. The daily
brief comes from the actor-scoped Archetype digest. `Start work` creates a
preview; only `Assign to me` executes the intent. Archetype rechecks permission,
expiry, finding state, and the canonical active Okta assignee before recording
the assignment.

Do not configure a static Slack-to-user map for this path. Okta and Archetype
source errors fail closed, and the runtime never substitutes local identity or
finding data.
