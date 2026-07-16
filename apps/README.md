# Applications

Applications in this directory are public, portable clients of Cerebro contracts.

- `web` owns the browser application, server-side web proxy, and UI tests.
- `slack-companion` owns Slack admission, durable run coordination, delivery, and Slack-visible lifecycle behavior.

Each application is an npm workspace with its own private package manifest and independent build entrypoint. Applications may depend on public schemas and SDKs in this repository. The Go runtime does not import application code, serve application assets, or require an application to start.

Environment-specific deployment adapters, network configuration, secret addresses, rollout policy, and recovery policy do not belong under `apps/`.
