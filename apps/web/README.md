# Cerebro Web

Cerebro Web is the browser application for the public Cerebro API and OpenAPI contracts. It is an independent npm workspace: the Go service does not import or serve this application.

## Develop

From the repository root:

```sh
npm ci
npm run dev --workspace @writer/cerebro-web
```

Use fixture mode when no Cerebro server is running:

```sh
npm run dev:fixtures --workspace @writer/cerebro-web
```

## Check

```sh
npm run check --workspace @writer/cerebro-web
npm run build --workspace @writer/cerebro-web
```

The app accepts public Cerebro API and identity configuration. Environment deployment adapters, network configuration, secret addresses, and rollout policy live outside this workspace.

This application retains its MIT license in [LICENSE](LICENSE). The rest of the repository remains under the root Apache 2.0 license unless a nested license states otherwise.
