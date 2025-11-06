# TypeScript SDK Guide

> Scope: internal Writer use only

The TypeScript SDK (`sdk/ts`) underpins frontend automation, integration services, and partner-facing tooling. It mirrors the platform API surface with strong typing, retry-aware networking, and shared serialization primitives. This guide walks through project layout, development workflows, and core modules so new contributors can extend the SDK with confidence.

## Project Layout

```
sdk/ts/
├── src/
│   ├── clients/            # High-level HTTP facades (agents, findings, integrations, security center, etc.)
│   ├── httpClient.ts       # Fetch-based client with middleware, retries, timeouts, and streaming helpers
│   ├── pagination.ts       # Cursor helpers, iterate/collect utilities
│   ├── serialization.ts    # CamelCase transforms, date coercion, OpenAPI adapters
│   ├── streaming.ts        # SSE parsing and async iterator helpers
│   ├── agents/             # Agent-specific streaming, security utilities
│   ├── securityCenter/     # Analytics, relations, GRC, evidence primitives
│   └── generated/          # OpenAPI-derived schema adapters (checked in)
├── test/                   # Vitest suites (unit, contract, integration)
├── package.json
└── tsconfig.json
```

The package targets modern runtimes (ES2022+) and ships ESM output. Avoid introducing CommonJS-only dependencies.

## Development Workflow

```bash
cd sdk/ts
npm install           # one-time dependency install

npm run lint          # type-check via tsc --noEmit
npm run test          # vitest run (deterministic, fast)
npm run test:watch    # hot reload support during development

npm run build         # compile to dist/ for publication (internal registry)
```

Pre-commit CI mirrors these commands. When adding new files, ensure they are referenced in the barrel export (`src/index.ts`) so downstream consumers receive typings.

## HTTP Client Architecture

`HttpClient` wraps `fetch` and standardises platform-specific requirements:

| Feature | Details |
| --- | --- |
| Retries | Exponential backoff with jitter, opt-in per request. |
| Middleware | `beforeRequest` / `afterResponse` hooks for auth injection, logging, or instrumentation. |
| Timeouts | AbortController-based cancellation with configurable default. |
| Streaming | `sendStream` exposes `ReadableStream`/async iterator consumption. |
| Error Normalisation | Non-2xx responses throw enriched `HttpError` with parsed JSON body when available. |

Extend `HttpClient` sparingly; prefer composing middleware in consumer packages.

## Serialization & OpenAPI Adapters

`serialization.ts` houses `transformOpenApi`, `camelizeKeys`, and targeted date parsing utilities. Generated adapters (`src/generated/adapters/schemaAdapters.ts`) map raw API responses onto strongly typed records. When the API introduces new fields:

1. Update the OpenAPI spec and rerun `npm run generate:schemas` (script lives in `scripts/generate-types.mjs`).
2. Inspect generated adapters for date metadata and ensure relevant modules import the new types.
3. Write Vitest coverage to lock behaviour.

Avoid manual camel-case interfaces; rely on `Camelize<T>` and generated adapters to stay in sync with the API schema.

## Pagination Utilities

`pagination.ts` standardises cursor pagination:

```ts
import { iterateCursor, collectCursor, PageRequest } from "@cerebro/sdk";

const page: PageRequest = { cursor: undefined, limit: 100 };
for await (const record of iterateCursor(() => client.listAgents(page))) {
  // process record
}

const allFindings = await collectCursor(() => findingsClient.list({ orgId }));
```

When implementing new client methods, expose both a raw paginated call (returning `{ items, nextCursor }`) and a convenience generator using these helpers.

## Streaming & Event Handling

Agent workloads and GRC telemetry leverage server-sent events (SSE). The SDK offers two layers:

- `streaming.ts` exports `parseServerSentEvents` (low level async generator) and `toServerSentEventIterator` (bridge to standard async iteration).
- `agents/streaming.ts` wraps event payloads with type guards (`isCompletionEvent`, `isToolCallEvent`) and convenience collectors (`collectAgentStream`).

When integrating new streaming endpoints, reuse these primitives before introducing bespoke parsing logic.

## Security Center Modules

Recent enhancements add a rich Security Center namespace:

| Module | Purpose |
| --- | --- |
| `securityCenter/analytics.ts` | Vendor/customer health scoring, trend analysis, anomaly detection. |
| `securityCenter/relations.ts` | Relations index, exposure dashboards, entity-aware streaming enrichment. |
| `securityCenter/grc.ts` | Control mapping, evidence bundle generation, lifecycle summaries. |
| `securityCenter/remediation.ts` | Remediation queue generation with severity banding and SLA targets. |
| `securityCenter/alerts.ts` | Monitoring event evaluation, governance escalation routing. |
| `securityCenter/primitives.ts` | Canonical `EntityProfile`, `EvidenceArtifact`, lifecycle policy evaluation. |

Consumers can assemble higher-level dashboards by first extracting `EvidenceArtifact` sets, running `summarizeEvidenceSet`, then feeding the results into control mapping or remediation pipelines.

## Testing Strategy

Vitest suites cover:

- Unit tests under `test/` grouped by domain. Names mirror `src/` modules (`securityCenterPrimitives.test.ts`, `securityCenterRelations.test.ts`, etc.).
- Contract tests (`test/contract/*.test.ts`) against the mock server to ensure HTTP facades align with API fixtures.
- Integration smoke tests (`test/integration/sdk.integration.test.ts`) exercising key agent flows end-to-end.

When adding modules:

1. Place unit tests beside existing suites (naming convention `*.test.ts`).
2. Update `package.json` test scripts if additional environment setup is required (avoid, when possible).
3. Run `npm run test -- --runInBand` in CI to keep concurrency deterministic.

## Publishing & Versioning

Releases are handled through internal automation:

1. Bump the version in `package.json` following semver (major for breaking API changes, minor for new features, patch for fixes).
2. Run `npm run build` to generate `dist/` artifacts.
3. Publish to the internal registry (e.g., `npm publish --registry=https://npm.writer.tools`).
4. Update downstream services via Renovate or manual dependency bumps.

Document new APIs in this guide (or module-specific docs) so consumers understand expectations before upgrading.

## Troubleshooting

| Symptom | Likely Cause | Fix |
| --- | --- | --- |
| `TypeError: fetch is not a function` | Running in Node <18 without polyfill. | Upgrade runtime or install `undici` and set `globalThis.fetch`. |
| `HttpError` with empty body | Endpoint returning non-JSON error. | Inspect `error.response` headers, add guard for plaintext responses. |
| Generated adapter missing field | OpenAPI schema stale. | Regenerate adapters and commit changes. |
| SSE stream terminates early | Timeout triggered or connection closed. | Increase `timeoutMs` in `HttpClient.sendStream` options, examine server logs. |

## Further Reading

- [SDK Overview](README.md)
- [Integrations and Playbooks](integrations-and-playbooks.md)
- [Security Center Evidence Lifecycle (Python parity)](../security-center.md) – domain concepts that inform TypeScript helpers
- Source references in `sdk/ts/test/` for example usage patterns
