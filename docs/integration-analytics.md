# Integration Analytics Guide

This guide explains how to pull integration coverage data through the Cerebro TypeScript SDK, derive health and trend metrics, and troubleshoot common authentication issues.

## Prerequisites

- Install `@cerebro/sdk`
- An API key or access token with permission to query integration endpoints
- Base URL for your Cerebro environment

## Authenticating Requests

```ts
import { CerebroSDK } from "@cerebro/sdk";

const sdk = new CerebroSDK({
  baseUrl: process.env.CEREBRO_BASE_URL!,
  apiKey: process.env.CEREBRO_API_KEY!,
});
```

If you see `401 status code (no body)`:

1. Verify the API key or token is set and not expired.
2. Make sure the key has access to the `/api/v1/integrations/*` routes.
3. Ensure your base URL is correct (production vs staging).
4. If you rely on OAuth tokens, pass `getAccessToken` instead of `apiKey`.

```ts
const sdk = new CerebroSDK({
  baseUrl: process.env.CEREBRO_BASE_URL!,
  getAccessToken: async () => refreshTokenSomehow(),
});
```

## Fetching Coverage Snapshots

```ts
const coverage = await sdk.integrations.getCoverage({ staleSeconds: 300 });
```

- `integration` narrows results to a single integration.
- `staleSeconds` asks the platform to reuse cached measurements when possible.

Each `IntegrationCoverageRecord` contains status, scope counts, and timestamps (`evaluatedAt`, `lastSuccess`).

## Pulling Historical Coverage

Use `getCoverageHistory` to fetch time-series snapshots for trend analysis.

```ts
const history = await sdk.integrations.getCoverageHistory({
  integration: "github",
  since: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
  until: new Date(),
  limit: 100,
});
```

The response uses the same shape as `getCoverage`. Combine multiple integrations by omitting the `integration` filter.

## Deriving Health Metrics

```ts
import { computeCoverageHealthMap } from "@cerebro/sdk";

const healthByIntegration = computeCoverageHealthMap(coverage);
const githubHealth = healthByIntegration.github;

console.log(githubHealth.healthyPercentage); // e.g. 0.72
console.log(githubHealth.overallScore);      // weighted score factoring warnings/critical scopes
```

## Building Integration Overviews

`buildIntegrationOverviewMap` merges coverage, findings, and organizations for a holistic snapshot.

```ts
import { buildIntegrationOverviewMap } from "@cerebro/sdk";

const findings = await sdk.findings.list();
const organizations = await sdk.organizations.list();

const overview = buildIntegrationOverviewMap({
  coverage,
  findings,
  organizations,
});

const github = overview.github;
console.log(github.openFindings);                // open findings tied to GitHub providers
console.log(github.findingsBySeverity.high ?? 0); // severity rollups
```

Optional `providerAliases` let you map custom provider names to integrations:

```ts
buildIntegrationOverviewMap({
  coverage,
  findings,
  organizations,
  providerAliases: {
    github: ["gh", "gitlab"],
  },
});
```

## Trend and Anomaly Detection

```ts
import { computeCoverageTrendForIntegration } from "@cerebro/sdk";

const trend = computeCoverageTrendForIntegration("github", history, {
  windowSize: 4,
  anomalyThreshold: 0.1,
  criticalThreshold: 0.2,
});

if (trend.anomaly) {
  console.warn(
    `Coverage fell by ${Math.abs(trend.anomaly.delta).toFixed(3)} in the last sample (severity: ${trend.anomaly.severity})`,
  );
}

console.log(trend.latestChange); // difference between last two samples
console.log(trend.warnings);     // normalization warnings (e.g., clipped ratios)
```

### Option Validation

- `windowSize` must be positive.
- `anomalyThreshold` / `criticalThreshold` must be non-negative.
- Thresholds represent absolute ratio deltas (e.g., `0.15` = 15% drop).

## Workflow Summary

1. Fetch current coverage (`getCoverage`) to populate dashboards quickly.
2. Hydrate history (`getCoverageHistory`) on a schedule for time-series storage.
3. Derive health via `computeCoverageHealthMap`.
4. Merge coverage with findings/orgs using `buildIntegrationOverviewMap`.
5. Detect dips with `computeCoverageTrendForIntegration` and alert on anomalies.

By layering these helpers, you can spot integration regressions early and keep stakeholders informed with actionable metrics.
