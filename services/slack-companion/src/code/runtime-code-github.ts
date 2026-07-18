import { createSign } from "node:crypto";
import type { AppConfig } from "../config/index.js";

export function githubChecksSummary(
  runs: Array<{ status?: string; conclusion?: string | null }>,
  statuses: Array<{ state?: string }>,
  combinedStatus: string | undefined,
): Record<string, number | string> {
  const failedRuns = runs.filter((run) => ["failure", "timed_out", "cancelled", "action_required"].includes(run.conclusion ?? "")).length;
  const pendingRuns = runs.filter((run) => run.status !== "completed" || !run.conclusion).length;
  const passedRuns = runs.filter((run) => run.status === "completed" && run.conclusion === "success").length;
  const failedStatuses = statuses.filter((status) => status.state === "failure" || status.state === "error").length;
  const pendingStatuses = statuses.filter((status) => status.state === "pending").length;
  const passedStatuses = statuses.filter((status) => status.state === "success").length;
  const failed = failedRuns + failedStatuses;
  const pending = pendingRuns + pendingStatuses;
  const passed = passedRuns + passedStatuses;
  const state = failed > 0 ? "failed" : pending > 0 ? "pending" : passed > 0 ? "passed" : combinedStatus ?? "unknown";
  return {
    state,
    passed,
    failed,
    pending,
    check_runs: runs.length,
    statuses: statuses.length,
  };
}

export function githubAppJwt(app: NonNullable<AppConfig["code"]["githubApp"]>): string {
  const now = Math.floor(Date.now() / 1000);
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64Url(JSON.stringify({
    iat: now - 60,
    exp: now + 540,
    iss: app.appId,
  }));
  const signingInput = `${header}.${payload}`;
  const privateKey = Buffer.from(app.privateKeyBase64, "base64").toString("utf8");
  const signature = createSign("RSA-SHA256")
    .update(signingInput)
    .end()
    .sign(privateKey, "base64url");
  return `${signingInput}.${signature}`;
}

export async function assertGithubOk(response: Response): Promise<void> {
  if (response.ok) return;
  const text = await response.text().catch(() => "");
  throw new Error(`GitHub API failed ${response.status}: ${text.slice(0, 500)}`);
}

function base64Url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}
