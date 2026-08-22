# Applications

`apps/` contains Cerebro's public operator surfaces. They live in this monorepo because they consume the same contracts as the Go runtime and should move with those contracts when behavior changes.

| Workspace | Package | Owns |
| --- | --- | --- |
| `web` | `@writer/cerebro-web` | Browser operator UI, server-side web boundary, UI contracts, and web tests. |
| `slack-companion` | `@writer/cerebro-slack-companion` | Slack intake, durable run coordination, delivery, background work, and Slack-visible lifecycle behavior. See [Slack companion](slack-companion/README.md). |
| `slack-companion-host` | `@writer/cerebro-slack-companion-host` | Executable Slack runtime, transport adapters, tool registration, durable outcome handling, and host-side enforcement. See [Slack companion host](slack-companion-host/README.md). |

Each app is an npm workspace with its own `package.json`. The package manifests use `private: true` to prevent accidental npm publication; that does not mean the code belongs in a private repository.

Apps may depend on public schemas, generated bindings, SDKs, and other portable workspaces in this repo. The Slack host depends on the portable Slack companion. The Go and Rust runtimes do not import app code, serve app assets, or require an app to start.

Do not put environment-specific deployment adapters, network configuration, secret addresses, rollout policy, or recovery policy under `apps/`. Keep those in private operations repositories and expose only portable interfaces, fixtures, and conformance tests here. See [Monorepo Ownership And Boundaries](../docs/engineering/monorepo.md) for the canonical split.
