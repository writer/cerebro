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

Run the browser against the Rust-owned organizational graph without Docker or provider credentials:

```sh
make rust-product-demo
```

The command prints graph explorer and vendor register URLs and stops all local processes on `Ctrl-C`. With Chromium installed, `make rust-product-demo-check` validates the direct Rust response, the web proxy, the rendered graph, and the Go-compatible GRC vendor read backed by the Rust graph, then writes `tmp/rust-product-demo/receipt.json` without the ephemeral authentication secret.

## Check

```sh
npm run check --workspace @writer/cerebro-web
npm run build --workspace @writer/cerebro-web
npm run e2e:web:fixtures --workspace @writer/cerebro-web
```

`e2e:web:fixtures` starts the web application with synthetic, local fixture data and validates its public routes in Chromium. It does not start a Cerebro service or persistent stores; real service integration remains a separate test lane.

Run the real-service integration when Docker, Go, and Rust are available:

```sh
npm run e2e:grc:local --workspace @writer/cerebro-web
```

`e2e:grc:local` starts disposable local stores, seeds synthetic data, builds and starts Cerebro, validates backend and web proxy behavior, checks the browser routes in Chromium, and removes every service when the run finishes. Failed runs retain their local logs and screenshots at the path printed by the command.

The app accepts public Cerebro API and identity configuration. Environment deployment adapters, network configuration, secret addresses, and rollout policy live outside this workspace.

This application retains its MIT license in [LICENSE](LICENSE). The rest of the repository remains under the root Apache 2.0 license unless a nested license states otherwise.
