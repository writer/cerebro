import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { CerebroSDK } from "../../src/sdk";
import { collectAgentStream } from "../../src/agents/streaming";
import { buildIntegrationOverviewMap } from "../../src/integrations/overview";
import { computeCoverageTrendForIntegration } from "../../src/integrations/analytics";
import {
  assessCustomerHealth,
  assessVendorHealth,
  summarizeCustomerPortfolio,
  summarizeVendorPortfolio,
} from "../../src/securityCenter/analytics";

const fixturesDir = path.resolve(__dirname, "../fixtures");

describe("mock server harness", () => {
  let server: ReturnType<typeof createServer>;
  let baseUrl: string;

  beforeAll(async () => {
    server = createServer(async (req, res) => {
      const requestUrl = new URL(req.url ?? "", `http://${req.headers.host ?? "127.0.0.1"}`);
      if (req.method === "GET" && requestUrl.pathname === "/api/v1/agents/review-tasks") {
        await respondWithJson(res, "agents/review-tasks.json");
        return;
      }

      if (req.method === "GET" && requestUrl.pathname === "/api/v1/integrations/coverage") {
        await respondWithJson(res, "integrations/coverage.json");
        return;
      }

      if (req.method === "GET" && requestUrl.pathname === "/api/v1/integrations/coverage/history") {
        await respondWithFilteredHistory(res, requestUrl.searchParams, "integrations/coverage-history.json");
        return;
      }

      if (req.method === "GET" && requestUrl.pathname === "/api/v1/findings") {
        await respondWithJson(res, "findings/findings.json");
        return;
      }

      if (req.method === "GET" && requestUrl.pathname === "/api/v1/organizations") {
        await respondWithJson(res, "organizations/organizations.json");
        return;
      }

      if (req.method === "GET" && requestUrl.pathname.startsWith("/api/v1/security-center/organizations/") && requestUrl.pathname.endsWith("/vendors")) {
        await respondWithJson(res, "security-center/vendors.json");
        return;
      }

      if (req.method === "GET" && requestUrl.pathname.startsWith("/api/v1/security-center/organizations/") && requestUrl.pathname.endsWith("/customers")) {
        await respondWithJson(res, "security-center/customers.json");
        return;
      }

      if (req.method === "POST" && requestUrl.pathname.startsWith("/api/v1/agents/sessions/")) {
        const body = await readBody(req);
        const wantsStream = body.stream === true;

        if (wantsStream) {
          res.writeHead(200, {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
          });
          res.write("event: message\n");
          res.write("data: {\"message_id\":\"msg-1\",\"role\":\"assistant\",\"content\":\"Hello\"}\n\n");
          res.write("event: tool\n");
          res.write("data: {\"invocation_id\":\"tool-1\",\"status\":\"completed\"}\n\n");
          res.write("event: status\n");
          res.write("data: {\"status\":\"completed\"}\n\n");
          res.end();
          return;
        }

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            status: "ack",
            message_id: "msg-ack",
            created_at: new Date().toISOString(),
          }),
        );
        return;
      }

      res.statusCode = 404;
      res.end();
    });

    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        if (typeof address === "object" && address) {
          baseUrl = `http://${address.address}:${address.port}`;
        } else {
          throw new Error("Failed to start mock server");
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  });

  it("performs end-to-end flows against mock server", async () => {
    const sdk = new CerebroSDK({ baseUrl, apiKey: "test-key" });

    const tasks = await sdk.agents.listReviewTasks({ limit: 10 });
    expect(tasks).toHaveLength(1);
    expect(tasks[0]?.title).toBe("Check deployment");
    expect(tasks[0]?.dueAt?.toISOString()).toBe("2024-10-25T10:00:00.000Z");

    const coverageRecords = await sdk.integrations.getCoverage();
    expect(coverageRecords).toHaveLength(2);
    const githubCoverage = coverageRecords.find((entry) => entry.integration === "github");
    const pagerdutyCoverage = coverageRecords.find((entry) => entry.integration === "pagerduty");
    if (!githubCoverage || !pagerdutyCoverage) {
      throw new Error("expected coverage records for github and pagerduty");
    }
    expect(githubCoverage?.providers).toContain("gitlab");
    expect(githubCoverage?.coverageRatio).toBeCloseTo(0.75);
    expect(pagerdutyCoverage?.coverageRatio).toBeCloseTo(0.88);

    const coverageHealth = await sdk.integrations.getCoverageHealth();
    const githubHealth = coverageHealth.find((entry) => entry.integration === "github");
    const pagerdutyHealth = coverageHealth.find((entry) => entry.integration === "pagerduty");
    expect(githubHealth?.healthyPercentage).toBeGreaterThan(0.5);
    expect(githubHealth?.criticalPercentage).toBeGreaterThan(0);
    expect(pagerdutyHealth?.overallScore).toBeGreaterThan(githubHealth?.overallScore ?? 0);

    const githubHistory = await sdk.integrations.getCoverageHistory({ integration: "github" });
    expect(githubHistory).toHaveLength(2);
    const pagerdutyHistory = await sdk.integrations.getCoverageHistory({ integration: "pagerduty" });
    expect(pagerdutyHistory).toHaveLength(2);

    const findings = await sdk.findings.list();
    expect(findings).toHaveLength(2);
    expect(findings[0]?.findingId).toBe("finding-1");
    expect(findings[0]?.firstSeen?.toISOString()).toBe("2024-10-01T08:30:00.000Z");

    const organizations = await sdk.organizations.list();
    expect(organizations).toHaveLength(2);
    expect(organizations.some((org) => org.name === "Acme Corp")).toBe(true);
    expect(organizations.some((org) => org.name === "Globex")).toBe(true);

    const overviewMap = buildIntegrationOverviewMap({
      coverage: coverageRecords,
      findings,
      organizations,
    });
    const githubOverview = overviewMap.github;
    const pagerdutyOverview = overviewMap.pagerduty;
    expect(githubOverview?.openFindings).toBe(1);
    expect(githubOverview?.findingsBySeverity.high).toBe(1);
    expect(pagerdutyOverview?.openFindings).toBe(1);
    expect((pagerdutyOverview?.organizations ?? []).length).toBeGreaterThan(0);

    const trend = computeCoverageTrendForIntegration("github", githubHistory);
    expect(trend.latestChange).toBeLessThan(0);

    const vendorList = await sdk.securityCenter.listVendors("org-1");
    expect(vendorList.vendors).toHaveLength(2);
    const vendorPortfolio = summarizeVendorPortfolio(vendorList.vendors);
    expect(vendorPortfolio.total).toBe(2);
    expect(vendorPortfolio.overdueReviews).toBeGreaterThanOrEqual(0);
    const vendorAssessment = assessVendorHealth(vendorList.vendors[0]!);
    expect(vendorAssessment.vendorId).toBe("vendor-acme");

    const vendorSummaryViaClient = await sdk.securityCenter.summarizeVendorPortfolio("org-1");
    expect(vendorSummaryViaClient.total).toBe(2);
    const vendorAssessmentsViaClient = await sdk.securityCenter.assessVendorHealth("org-1");
    expect(vendorAssessmentsViaClient[0]?.vendorId).toBeDefined();

    const customerList = await sdk.securityCenter.listCustomers("org-1");
    expect(customerList.customers).toHaveLength(2);
    const customerPortfolio = summarizeCustomerPortfolio(customerList.customers);
    expect(customerPortfolio.total).toBe(2);
    const customerAssessment = assessCustomerHealth(customerList.customers[0]!);
    expect(customerAssessment.customerId).toBe("customer-alpha");

    const customerSummaryViaClient = await sdk.securityCenter.summarizeCustomerPortfolio("org-1");
    expect(customerSummaryViaClient.total).toBe(2);
    const customerAssessmentsViaClient = await sdk.securityCenter.assessCustomerHealth("org-1");
    expect(customerAssessmentsViaClient).toHaveLength(2);

    const streamResult = await sdk.agents.sendSessionMessage("session-123", {
      content: "Hi",
      stream: true,
    });

    expect(streamResult.kind).toBe("stream");
    const stream = streamResult.kind === "stream" ? streamResult.stream : undefined;
    if (!stream) throw new Error("Expected stream handle");

    const transcript = await collectAgentStream(stream);
    expect(transcript.messages).toHaveLength(1);
    expect(transcript.messages[0]?.content).toBe("Hello");
    expect(transcript.toolCalls).toHaveLength(1);
    expect(transcript.toolCalls[0]?.invocationId).toBe("tool-1");
    expect(transcript.completions.some((entry) => entry.done)).toBe(true);

    await stream.cancel();
  });
});

async function respondWithJson(res: ServerResponse, fixturePath: string) {
  const fullPath = path.join(fixturesDir, fixturePath);
  const raw = await readFile(fullPath, "utf8");
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(raw);
}

async function respondWithFilteredHistory(
  res: ServerResponse,
  params: URLSearchParams,
  fixturePath: string,
) {
  const fullPath = path.join(fixturesDir, fixturePath);
  const raw = await readFile(fullPath, "utf8");
  const entries = JSON.parse(raw) as Array<Record<string, unknown>>;

  const integration = params.get("integration")?.toLowerCase() ?? null;
  const since = params.get("since") ? new Date(params.get("since")!) : null;
  const until = params.get("until") ? new Date(params.get("until")!) : null;
  const limit = params.get("limit") ? Number.parseInt(params.get("limit")!, 10) : null;

  let filtered = entries.filter((entry) => {
    if (integration && typeof entry.integration === "string" && entry.integration.toLowerCase() !== integration) {
      return false;
    }
    const evaluatedAt = entry.evaluated_at ? new Date(entry.evaluated_at as string) : null;
    if (evaluatedAt && since && evaluatedAt < since) {
      return false;
    }
    if (evaluatedAt && until && evaluatedAt > until) {
      return false;
    }
    return true;
  });

  if (Number.isFinite(limit) && limit !== null && limit >= 0) {
    filtered = filtered.slice(0, limit);
  }

  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(filtered));
}

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of req) {
    chunks.push(chunk as Uint8Array);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return {};
  }
}
