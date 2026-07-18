import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { ComplianceContextService } from "../src/compliance/context.js";
import { testConfig } from "./fixtures.js";

test("compliance context searches local writer/cerebro source snippets", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-compliance-"));
  await writeSource(root, "docs/domains/compliance-controls.md", [
    "# Compliance Controls",
    "",
    "Control profiles are reusable YAML selections for customer audit packets.",
    "Profiles can compose SOC 2 Security Core and cloud benchmark scopes.",
  ].join("\n"));
  await writeSource(root, "internal/compliance/control_profiles.yaml", [
    "version: \"2026-06-17\"",
    "profiles:",
    "  - id: soc2-security-core",
    "    name: SOC 2 Security Core",
    "    description: Security audit scope covering access, operations, and monitoring controls.",
  ].join("\n"));
  await writeSource(root, "policies/compliance/compliance-risk-assessment.yaml", [
    "metadata:",
    "  id: compliance-risk-assessment-annual",
    "  name: Annual Risk Assessment Completed",
    "spec:",
    "  remediation:",
    "    summary: Conduct a comprehensive risk assessment.",
  ].join("\n"));

  const service = new ComplianceContextService(testConfig({
    complianceContext: {
      localDir: root,
      cacheTtlMs: 60_000,
      maxFileBytes: 10_000,
      maxTotalBytes: 50_000,
    },
  }));

  const result = await service.search({ query: "SOC 2 control profiles audit scope", includeOverview: true }) as any;

  assert.equal(result.ok, true);
  assert.equal(result.source.mode, "local");
  assert.equal(result.source.repo, "writer/cerebro");
  assert.ok(result.results.length > 0);
  assert.match(result.results[0].excerpt, /SOC 2|control profiles|audit scope/i);
  assert.match(JSON.stringify(result.skipped_sources), /control_coverage_index/);
});

test("compliance context caches GitHub raw fetches and skips oversized files", async () => {
  const calls: string[] = [];
  const bodyByPath = new Map<string, string>([
    ["docs/domains/compliance-controls.md", "# Compliance Controls\nEvidence expectations describe acceptable audit evidence."],
    ["internal/compliance/control_families.yaml", "x".repeat(200)],
  ]);
  const fetchImpl: typeof fetch = async (url) => {
    const href = String(url);
    calls.push(href);
    const path = href.split("/main/")[1] ?? "";
    const body = bodyByPath.get(path);
    if (body === undefined) {
      return new Response("missing", { status: 404 });
    }
    if (path === "internal/compliance/control_families.yaml") {
      return new Response(body, { status: 200 });
    }
    return new Response(body, {
      status: 200,
      headers: { "content-length": String(Buffer.byteLength(body, "utf8")) },
    });
  };

  const service = new ComplianceContextService(testConfig({
    complianceContext: {
      maxFileBytes: 100,
      maxTotalBytes: 5000,
      cacheTtlMs: 60_000,
    },
  }), { fetch: fetchImpl });

  const first = await service.search({ query: "evidence expectations audit evidence", includeOverview: true }) as any;
  const callCount = calls.length;
  const second = await service.search({ query: "acceptable audit evidence" }) as any;

  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  assert.equal(calls.length, callCount);
  assert.match(first.results[0].excerpt, /Evidence expectations/);
  assert.match(first.results[0].source_url, /^https:\/\/github\.com\/writer\/cerebro\/blob\/main\//);
  assert.ok(first.skipped_sources.some((source: any) => source.path === "internal/compliance/control_families.yaml" && source.reason === "file_bytes_limit"));
  assert.ok(first.skipped_sources.some((source: any) => source.path === "internal/compliance/control_coverage_index.yaml"));
});

async function writeSource(root: string, path: string, content: string): Promise<void> {
  const target = join(root, path);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, content, "utf8");
}
