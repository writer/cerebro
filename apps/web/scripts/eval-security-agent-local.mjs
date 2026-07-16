#!/usr/bin/env node

import {
  assertLocalURL,
  nowISO,
  reportTotals,
  scoreRubrics,
  writeReport,
} from "./eval-lib.mjs";

const agentURL = (process.env.SECURITY_AGENT_PLATFORM_URL ?? "http://127.0.0.1:18080").replace(/\/+$/, "");
const outputDir = process.env.CEREBRO_SECURITY_AGENT_EVAL_OUT_DIR ?? ".eval-reports/security-agent";

async function requestJSON(url, init) {
  const res = await fetch(url, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`${url} failed (${res.status}): ${text}`);
  }
  return text ? JSON.parse(text) : {};
}

function latestAssistant(session) {
  const messages = Array.isArray(session.messages) ? session.messages : [];
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    if (messages[index].role === "assistant") return messages[index].content ?? "";
  }
  return "";
}

async function main() {
  assertLocalURL(agentURL, "SECURITY_AGENT_PLATFORM_URL");

  const startedAt = Date.now();
  const question = "Use local Cerebro data to summarize open high findings and connector freshness for this repository.";
  const session = await requestJSON(`${agentURL}/v1/sessions`, {
    method: "POST",
    body: JSON.stringify({
      agent_id: "investigation",
      subject: "Cerebro cross-repo local eval",
      incident_id: "cerebro-cross-repo-local-eval",
      entity_id: "urn:cerebro:example:repo:example/security-repository",
    }),
  });
  const updated = await requestJSON(`${agentURL}/v1/sessions/${session.id}/messages`, {
    method: "POST",
    body: JSON.stringify({ content: question }),
  });

  const completedAt = Date.now();
  const response = latestAssistant(updated);
  const toolRuns = Array.isArray(updated.tool_runs) ? updated.tool_runs : [];
  const rubrics = [
    {
      id: "assistant-response",
      label: "assistant produced a response",
      passed: response.trim().length > 0,
      detail: `${response.length} chars`,
    },
    {
      id: "tool-runs",
      label: "agent executed Cerebro tools",
      passed: toolRuns.length > 0,
      detail: `${toolRuns.length} tool runs`,
    },
    {
      id: "no-failed-tools",
      label: "no tool run failed",
      passed: toolRuns.every((run) => run.status !== "failed"),
      detail: toolRuns.map((run) => `${run.tool_id}:${run.status}`).join(", "),
    },
    {
      id: "summary-signal",
      label: "response mentions evidence or findings",
      passed: /finding|connector|evidence|risk|quality/i.test(response),
      detail: response.slice(0, 180),
    },
  ];
  const score = scoreRubrics(rubrics);
  const status = rubrics.every((rubric) => rubric.passed) ? "passed" : "failed";
  const durationMs = completedAt - startedAt;

  const run = {
    id: "security-agent-cross-repo",
    kind: "security-agent",
    name: "Security Agent cross-repo local eval",
    question,
    tenantId: "writer",
    model: "deterministic-security-agent",
    scopeUrn: updated.entity_id,
    status,
    score,
    startedAt: new Date(startedAt).toISOString(),
    completedAt: new Date(completedAt).toISOString(),
    durationMs,
    rowCount: toolRuns.length,
    citationCount: 0,
    cypherRefused: false,
    summary: response,
    rubrics,
  };
  const report = await writeReport({
    generatedAt: nowISO(),
    localOnly: true,
    totals: reportTotals([run]),
    runs: [run],
  }, outputDir);

  console.log(JSON.stringify(report, null, 2));
  if (report.totals.failed > 0) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
