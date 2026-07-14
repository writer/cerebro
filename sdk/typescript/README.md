# Cerebro TypeScript SDK Helpers

The TypeScript helpers target the current Cerebro bootstrap API. They are maintained directly in this folder and are separate from the retired historical Agent SDK gateway.

## Install For Local Development

```bash
cd sdk/typescript
npm ci
```

The package is ESM and exports the base client plus the Jira posture helper entrypoint.
Source-runtime and platform-job methods use the types generated from `openapi.yaml`; `make openapi-ts-check` verifies that contract before SDK checks run.

## Client Basics

```typescript
import { Client } from "@writer/cerebro-sdk";

const client = new Client({
  baseUrl: "http://127.0.0.1:8080",
  apiKey: undefined, // Set when CEREBRO_API_AUTH_ENABLED=true.
});

const integration = client.integration({
  runtimeId: "local-sdk-demo",
  tenantId: "local",
  integration: "demo",
});

await integration.ensureRuntime();
const subject = integration.ref("service", "example-api", "Example API");
await integration.writeClaims([
  integration.attr(subject, "owner", "platform", {
    source_event_id: "demo-claim-1",
  }),
]);
```

Useful environment variables for examples:

```bash
export CEREBRO_BASE_URL=http://127.0.0.1:8080
export CEREBRO_API_KEY=
export CEREBRO_TENANT_ID=local
export CEREBRO_RUNTIME_ID=local-jira-posture
```

The Jira posture example lives at `examples/jira_posture_onboarding.ts`. Run it with your preferred TypeScript runner, or use the source as a reference for application onboarding.

## Checks

```bash
npm test
npm run typecheck
# Or from the repository root:
make sdk-typescript-test
make sdk-typescript-check
make sdk-dependency-audit
```

Use `make sdk-test` from the repository root when changes affect shared SDK behavior.
