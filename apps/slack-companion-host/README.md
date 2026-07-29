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

## Thread scratchpad

People can keep short-lived working context with the bot inside one Slack
thread:

- `@Cerebro remember <note>` or `@Cerebro scratchpad add <note>` saves a note.
- `@Cerebro scratchpad` shows the current notes.
- `@Cerebro clear scratchpad` removes every note in the thread.

After Cerebro delivers a citation-validated answer, it saves a bounded
question-and-answer note without waiting for a command. This gives later turns
working continuity beyond Slack's bounded history window. Autonomous notes
carry a hashed `/grc/ask` trace reference. They do not replace or evict notes
that a person explicitly saved.

The runtime uses saved notes for later questions only in the same workspace,
channel, and thread. Notes expire seven days after they are saved. A scratchpad
holds at most 20 notes and 8 KB of text. Credential-shaped values are redacted
before storage, and saved text is treated as untrusted context: it cannot grant
tool authority or override current Cerebro evidence.

Scratchpads use `CEREBRO_SLACK_RUNTIME_MEMORY_DIR` alongside the durable outcome
store. The deployment must mount that directory on persistent storage if notes
must survive a task or container replacement.

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
## Computer sandbox gateways

The host adapter accepts one or more private computer sandbox gateways through
`CEREBRO_COMPUTER_SANDBOX_GATEWAYS_JSON`. Each entry contains only routing
metadata:

```json
[
  {
    "base_url": "https://sandbox-gateway.example.internal",
    "provider_id": "interactive-primary",
    "timeout_ms": 30000,
    "token_env": "CEREBRO_COMPUTER_SANDBOX_TOKEN_INTERACTIVE_PRIMARY"
  }
]
```

The referenced token environment variables must be injected separately by the
deployment. Provider credentials, account identifiers, provider payloads, and
raw screenshots or files must not be included in the JSON binding.

The gateway implements the versioned routes under
`/v1/computer-sandbox`. It advertises only capabilities and actions that its
current provider adapter can execute. The portable coordinator selects a
compatible provider deterministically and fails over only after a gateway
proves that no session was created. An unknown create or action result must be
reconciled with the same gateway before retry.

Loading gateway configuration does not register model tools by itself. The
agent runtime composition must create the coordinator with
`createComputerSandboxRuntime` and register the portable computer tool catalog
through its host-owned tool registry.
