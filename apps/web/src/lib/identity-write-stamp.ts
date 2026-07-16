const ASSET_REPORT_TRIAGE_PATH = /^grc\/inventory\/asset-reports\/[^/]+\/triage$/;

export type CurrentUserWriteField = "reporter" | "triaged_by";

export function normalizeProxyPath(path: string) {
  return path.replace(/^\/+|\/+$/g, "");
}

export function currentUserWriteFieldForPath(path: string): CurrentUserWriteField | null {
  const normalizedPath = normalizeProxyPath(path);
  if (normalizedPath === "grc/inventory/asset-reports") return "reporter";
  if (ASSET_REPORT_TRIAGE_PATH.test(normalizedPath)) return "triaged_by";
  return null;
}

export function stampCurrentUserOnWriteBody(body: string, path: string, actor: string): string {
  const normalizedActor = actor.trim();
  if (!normalizedActor) return body;

  const field = currentUserWriteFieldForPath(path);
  if (!field) return body;

  try {
    const parsed = JSON.parse(body) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return body;

    return JSON.stringify({
      ...parsed,
      [field]: normalizedActor,
    });
  } catch {
    return body;
  }
}
