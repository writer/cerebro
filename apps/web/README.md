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

## Authentication modes

The web server proxies every Cerebro API call through `/api/cerebro`, so the browser never talks to the Cerebro service directly. The proxy authenticates in one of two ways:

| Mode | How it is configured | Where the credential lives | Use it for |
| --- | --- | --- | --- |
| Server-held credential (**deployment default**) | Set `CEREBRO_API_KEY` (or `CEREBRO_BEARER_TOKEN`) in the web server's environment as a secret. | Web server process only; the browser sees `Server auth` and its API key field is disabled. | Every shared, hosted, or production-like deployment. |
| Browser-held key (**local development only**) | Leave the server credential unset, or set `CEREBRO_FORWARD_AUTH_HEADERS=true`. Paste a key into the API key field in the top bar. | `window.localStorage` under `cerebro.apiKey`, sent as `X-API-Key` on each proxied request. | Pointing a local `next dev` at a local Cerebro, and nothing else. |

Do not deploy the browser-held mode: a key in `localStorage` is readable by any script that runs on the page, so a single XSS bug would leak it. Configure the server-held credential and keep `CEREBRO_FORWARD_AUTH_HEADERS` unset so a pasted key is never forwarded.

Every document is served with a nonce-based `Content-Security-Policy` (`script-src 'self' 'nonce-<per-request>' 'strict-dynamic'`, no `'unsafe-inline'`), generated in `src/proxy.ts`. Pages render per request so that the nonce reaches every script tag; `npm run smoke:standalone` fails if a rendered page ships a script without it.

The app accepts public Cerebro API and identity configuration. Environment deployment adapters, network configuration, secret addresses, and rollout policy live outside this workspace.

This application retains its MIT license in [LICENSE](LICENSE). The rest of the repository remains under the root Apache 2.0 license unless a nested license states otherwise.
