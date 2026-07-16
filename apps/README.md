# Applications

Applications in this directory are public, portable clients of Cerebro contracts.
They are npm workspaces owned by the public monorepo and built independently
from the Go runtime.

| Workspace | Package | Owns |
| --- | --- | --- |
| `web` | `@writer/cerebro-web` | Browser application, server-side web proxy, UI contracts, and web tests. |
| `slack-companion` | `@writer/cerebro-slack-companion` | Slack admission, durable run coordination, delivery, question work, distributed workcells, and Slack-visible lifecycle behavior. |

Each application has its own private package manifest and independent build
entrypoint. Applications may depend on public schemas and SDKs in this
repository. The Go runtime does not import application code, serve application
assets, or require an application to start.

Environment-specific deployment adapters, network configuration, secret
addresses, rollout policy, and recovery policy do not belong under `apps/`.
Keep those concerns in private deployment repositories and expose only portable
interfaces, fixtures, and tests here.
