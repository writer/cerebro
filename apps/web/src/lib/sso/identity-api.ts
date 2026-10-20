import { buildCerebroUrl, fetchCerebro, serviceAuthHeaders } from "@/lib/cerebro-proxy";
import { isCerebroFixtureMode } from "@/lib/fixture-mode";

import {
  DEFAULT_SSO_POLICY,
  type DirectoryUser,
  type SSOConnection,
  type SSOPolicy,
  type SSOSession,
  type SSOSessionCreate,
} from "./types";

const IDENTITY_PREFIX = "platform/identity";
const DEFAULT_TIMEOUT_MS = 10_000;

export type IdentityApiResponse = {
  status: number;
  body: string;
  contentType: string;
};

export type IdentityApiRequest = {
  search?: string;
  body?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
};

export class IdentityApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

const json = (payload: unknown, status = 200): IdentityApiResponse => ({
  status,
  body: payload === undefined ? "" : JSON.stringify(payload),
  contentType: "application/json; charset=utf-8",
});

/** Fixture mode has no Go API: SSO is unconfigured and not enforced, and writes are refused. */
export const identityFixtureResponse = (method: string, path: string): IdentityApiResponse => {
  const normalized = path.replace(/^\/+|\/+$/g, "");
  if (method === "GET") {
    if (normalized === "sso/connections") return json({ connections: [] });
    if (normalized === "sso/policy") return json(DEFAULT_SSO_POLICY);
    if (normalized === "scim/tokens") return json({ tokens: [] });
    if (normalized === "directory/users") return json({ users: [] });
    if (normalized === "directory/groups") return json({ groups: [] });
    if (normalized === "sessions") return json({ sessions: [] });
    return json({ error: "not_found" }, 404);
  }
  if (normalized.startsWith("scim/v2")) {
    return {
      status: 501,
      body: JSON.stringify({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        status: "501",
        detail: "SCIM is unavailable in fixture mode.",
      }),
      contentType: "application/scim+json",
    };
  }
  return json({ error: "SSO configuration is read-only in fixture mode." }, 409);
};

/**
 * Calls Go `/platform/identity/...` as the web service. Browser credentials are never forwarded: the
 * identity API is server-to-server only.
 */
export const identityApiRequest = async (
  method: string,
  path: string,
  { search = "", body, headers = {}, timeoutMs = DEFAULT_TIMEOUT_MS }: IdentityApiRequest = {},
): Promise<IdentityApiResponse> => {
  const upperMethod = method.toUpperCase();
  if (isCerebroFixtureMode()) return identityFixtureResponse(upperMethod, path);
  const target = buildCerebroUrl(`${IDENTITY_PREFIX}/${path.replace(/^\/+/, "")}`, search);
  const requestHeaders: Record<string, string> = {
    Accept: "application/json",
    ...headers,
    ...serviceAuthHeaders(),
  };
  if (body !== undefined && !Object.keys(requestHeaders).some((name) => name.toLowerCase() === "content-type")) {
    requestHeaders["Content-Type"] = "application/json";
  }
  const response = await fetchCerebro(target, {
    method: upperMethod,
    headers: requestHeaders,
    body,
    cache: "no-store",
    signal: AbortSignal.timeout(timeoutMs),
  });
  return {
    status: response.status,
    body: await response.text(),
    contentType: response.headers.get("content-type") ?? "application/json",
  };
};

const parseJson = <T>(response: IdentityApiResponse): T => {
  try {
    return JSON.parse(response.body) as T;
  } catch {
    throw new IdentityApiError("Identity API returned invalid JSON.", 502);
  }
};

const expectStatus = <T>(response: IdentityApiResponse, ...statuses: number[]): T => {
  if (!statuses.includes(response.status)) {
    throw new IdentityApiError(`Identity API request failed with status ${response.status}.`, response.status);
  }
  return response.body ? parseJson<T>(response) : (undefined as T);
};

export const fetchSsoPolicy = async (): Promise<SSOPolicy> => {
  const response = await identityApiRequest("GET", "sso/policy");
  return { ...DEFAULT_SSO_POLICY, ...expectStatus<Partial<SSOPolicy>>(response, 200) };
};

export const fetchSsoConnections = async (): Promise<SSOConnection[]> => {
  const response = await identityApiRequest("GET", "sso/connections");
  const payload = expectStatus<{ connections?: SSOConnection[] }>(response, 200);
  return Array.isArray(payload?.connections) ? payload.connections : [];
};

export const fetchSsoConnection = async (connectionId: string): Promise<SSOConnection | null> => {
  const response = await identityApiRequest("GET", `sso/connections/${encodeURIComponent(connectionId)}`);
  if (response.status === 404) return null;
  return expectStatus<SSOConnection>(response, 200);
};

export const postConnectionTestResult = async (connectionId: string, result: { ok: boolean; actor: string; detail: string }) => {
  const response = await identityApiRequest("POST", `sso/connections/${encodeURIComponent(connectionId)}/test-result`, {
    body: JSON.stringify(result),
  });
  return expectStatus<SSOConnection>(response, 200, 201);
};

export const lookupSsoSession = async (tokenHash: string): Promise<SSOSession | null> => {
  const response = await identityApiRequest("GET", `sessions/${tokenHash}`, { timeoutMs: 5_000 });
  if (response.status === 404) return null;
  return expectStatus<SSOSession>(response, 200);
};

export const createSsoSession = async (input: SSOSessionCreate): Promise<SSOSession> => {
  const response = await identityApiRequest("POST", "sessions", { body: JSON.stringify(input) });
  return expectStatus<SSOSession>(response, 200, 201);
};

export const deleteSsoSession = async (tokenHash: string) => {
  const response = await identityApiRequest("DELETE", `sessions/${tokenHash}`);
  if (response.status !== 204 && response.status !== 200 && response.status !== 404) {
    throw new IdentityApiError(`Identity API request failed with status ${response.status}.`, response.status);
  }
};

export const lookupDirectoryUser = async (connectionId: string, email: string): Promise<DirectoryUser | null> => {
  const search = `?${new URLSearchParams({ connectionId, email }).toString()}`;
  const response = await identityApiRequest("GET", "directory/users/lookup", { search });
  if (response.status === 404) return null;
  return expectStatus<DirectoryUser>(response, 200);
};

export const upsertJitDirectoryUser = async (input: {
  connectionId: string;
  subject: string;
  email: string;
  name: string;
  groups: string[];
}): Promise<DirectoryUser> => {
  const response = await identityApiRequest("POST", "directory/users/jit", { body: JSON.stringify(input) });
  return expectStatus<DirectoryUser>(response, 200, 201);
};
