import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { LoginTransaction } from "./tx";
import { DEFAULT_SSO_POLICY, type AssertedIdentity, type DirectoryUser, type SSOConnection, type SSOSessionCreate } from "./types";

const api = vi.hoisted(() => ({
  lookup: null as DirectoryUser | null,
  jit: null as DirectoryUser | null,
  jitError: null as null | { status: number; code: string },
  sessionError: null as null | { status: number; code: string },
  jitCalls: [] as unknown[],
  sessions: [] as SSOSessionCreate[],
}));

vi.mock("./identity-api", async (importOriginal) => {
  const original = await importOriginal<typeof import("./identity-api")>();
  return {
    ...original,
    lookupDirectoryUser: vi.fn(async () => api.lookup),
    upsertJitDirectoryUser: vi.fn(async (input: unknown) => {
      api.jitCalls.push(input);
      if (api.jitError) throw new original.IdentityApiError("refused", api.jitError.status, api.jitError.code);
      return api.jit;
    }),
    createSsoSession: vi.fn(async (input: SSOSessionCreate) => {
      if (api.sessionError) throw new original.IdentityApiError("refused", api.sessionError.status, api.sessionError.code);
      api.sessions.push(input);
      return input;
    }),
    postConnectionTestResult: vi.fn(async () => ({})),
    deleteSsoSession: vi.fn(async () => undefined),
  };
});

vi.mock("./policy", () => ({
  getSsoPolicyState: vi.fn(async () => ({ policy: DEFAULT_SSO_POLICY, source: "api" })),
}));

vi.mock("./session", () => ({ clearSsoSessionCache: vi.fn() }));

const { clientIpFrom, finishLogin } = await import("./finish");

const ORIGIN = "https://cerebro.example.com";

const connection: SSOConnection = {
  id: "conn-1",
  name: "Example",
  protocol: "oidc",
  status: "active",
  domains: ["example.com"],
  roleMappings: [{ group: "admins", roles: ["cerebro.admin"] }],
  defaultRoles: [],
  jitProvisioning: true,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  updatedBy: "test",
};

const tx: LoginTransaction = {
  connectionId: "conn-1",
  state: "state",
  returnTo: "/",
  test: false,
  createdAt: new Date().toISOString(),
};

const identity = (groups: string[] = [], subject = "subject-1"): AssertedIdentity => ({
  subject,
  email: "jane@example.com",
  name: "Jane",
  groups,
});

const directoryUser = (overrides: Partial<DirectoryUser> = {}): DirectoryUser => ({
  id: "usr-1",
  userName: "jane@example.com",
  email: "jane@example.com",
  name: "Jane",
  active: true,
  groups: [],
  scimGroups: [],
  jitGroups: [],
  source: "jit",
  connectionId: "conn-1",
  ...overrides,
});

beforeEach(() => {
  api.lookup = null;
  api.jit = directoryUser();
  api.jitError = null;
  api.sessionError = null;
  api.jitCalls = [];
  api.sessions = [];
});

const finish = (asserted: AssertedIdentity) => finishLogin(connection, asserted, tx, { origin: ORIGIN });

const expectGenericDenial = (response: Response) => {
  expect(response.status).toBe(303);
  expect(new URL(response.headers.get("location") ?? "").searchParams.get("error")).toBe("access_denied");
  expect(response.headers.get("set-cookie") ?? "").not.toMatch(/cerebro_session=[^;]/);
  expect(api.sessions).toEqual([]);
};

describe("session groups come from the fresh assertion and SCIM only", () => {
  it("drops a mapped role when the IdP stops sending the group, even if the directory still lists it", async () => {
    const stale = directoryUser({ groups: ["admins"], jitGroups: ["admins"] });
    api.lookup = stale;
    api.jit = stale;
    await finish(identity([]));
    expect(api.sessions).toHaveLength(1);
    expect(api.sessions[0].groups).toEqual([]);
    expect(api.sessions[0].roles).not.toContain("cerebro.admin");
  });

  it("keeps ignoring stored JIT groups after SCIM links the user", async () => {
    const linked = directoryUser({ source: "scim", groups: ["admins"], jitGroups: ["admins"], scimGroups: [] });
    api.lookup = linked;
    api.jit = linked;
    await finish(identity([]));
    expect(api.sessions[0].groups).toEqual([]);
    expect(api.sessions[0].roles).toEqual([]);
  });

  it("grants roles from SCIM-managed memberships and fresh assertion groups", async () => {
    const managed = directoryUser({ source: "scim", groups: ["admins", "old"], scimGroups: ["admins"], jitGroups: ["old"] });
    api.lookup = managed;
    api.jit = managed;
    await finish(identity(["security"]));
    expect(api.sessions[0].groups.sort()).toEqual(["admins", "security"]);
    expect(api.sessions[0].roles).toContain("cerebro.admin");
  });

  it("records every login through the JIT endpoint so Go can bind and check the subject", async () => {
    api.lookup = directoryUser({ source: "scim" });
    api.jit = directoryUser({ source: "scim" });
    await finish(identity([]));
    expect(api.jitCalls).toEqual([expect.objectContaining({ connectionId: "conn-1", subject: "subject-1", email: "jane@example.com" })]);
  });
});

describe("session cookie lifetime", () => {
  const cookieMaxAge = (response: Response) => Number(/cerebro_session=[^;]+;[^]*?Max-Age=(\d+)/i.exec(response.headers.get("set-cookie") ?? "")?.[1]);

  it("follows the expiry Go stored when it is shorter than the policy lifetime", async () => {
    const { createSsoSession } = await import("./identity-api");
    vi.mocked(createSsoSession).mockImplementationOnce(async (input: SSOSessionCreate) => {
      api.sessions.push(input);
      return { ...input, expiresAt: new Date(Date.now() + 2 * 3_600_000).toISOString() } as never;
    });
    const maxAge = cookieMaxAge(await finish(identity(["admins"])));
    expect(maxAge).toBeGreaterThan(2 * 3600 - 60);
    expect(maxAge).toBeLessThanOrEqual(2 * 3600);
  });

  it("uses the policy lifetime when Go keeps it", async () => {
    expect(cookieMaxAge(await finish(identity()))).toBe(DEFAULT_SSO_POLICY.sessionMaxLifetimeMinutes * 60);
  });
});

describe("signing in again", () => {
  it("revokes the session cookie the browser already held", async () => {
    const { deleteSsoSession } = await import("./identity-api");
    const { sessionTokenHash } = await import("./cookies");
    const previous = "p".repeat(43);
    await finishLogin(connection, identity(), tx, { origin: ORIGIN, previousSessionToken: previous });
    expect(vi.mocked(deleteSsoSession)).toHaveBeenCalledWith(sessionTokenHash(previous));
  });

  it("still signs in when revoking the old session fails", async () => {
    const { deleteSsoSession } = await import("./identity-api");
    vi.mocked(deleteSsoSession).mockRejectedValueOnce(new Error("down"));
    const response = await finishLogin(connection, identity(), tx, { origin: ORIGIN, previousSessionToken: "q".repeat(43) });
    expect(response.headers.get("set-cookie") ?? "").toMatch(/cerebro_session=[^;]/);
  });
});

describe("directory lookup", () => {
  it("passes the asserted subject so the subject-bound record wins", async () => {
    const { lookupDirectoryUser } = await import("./identity-api");
    await finish(identity([], "sub-42"));
    expect(vi.mocked(lookupDirectoryUser)).toHaveBeenLastCalledWith("conn-1", "jane@example.com", "sub-42");
  });
});

describe("directory refusals fail the login without a session", () => {
  it.each([
    ["a subject mismatch", { status: 409, code: "subject_mismatch" }],
    ["a deprovisioned user", { status: 403, code: "user_deprovisioned" }],
    ["an inactive user", { status: 403, code: "user_inactive" }],
  ])("refuses %s on an existing user", async (_label, error) => {
    api.lookup = directoryUser({ source: "scim" });
    api.jitError = error;
    expectGenericDenial(await finish(identity([], "other-subject")));
  });

  it("refuses a deprovisioned user that JIT would otherwise recreate", async () => {
    api.lookup = null;
    api.jitError = { status: 403, code: "user_deprovisioned" };
    expectGenericDenial(await finish(identity()));
  });

  it("refuses when the JIT endpoint returns an inactive user", async () => {
    api.lookup = directoryUser();
    api.jit = directoryUser({ active: false });
    expectGenericDenial(await finish(identity()));
  });

  it.each([
    ["inactive", "user_inactive"],
    ["deprovisioned", "user_deprovisioned"],
  ])("refuses when Go rejects session creation for an %s user", async (_label, code) => {
    api.lookup = directoryUser();
    api.sessionError = { status: 403, code };
    expectGenericDenial(await finish(identity()));
  });
});

describe("clientIpFrom", () => {
  const original = process.env.CEREBRO_WEB_TRUSTED_PROXY_HOPS;

  afterEach(() => {
    if (original === undefined) delete process.env.CEREBRO_WEB_TRUSTED_PROXY_HOPS;
    else process.env.CEREBRO_WEB_TRUSTED_PROXY_HOPS = original;
  });

  const forwarded = (value?: string) => new Headers(value === undefined ? {} : { "x-forwarded-for": value });

  it("uses the rightmost hop by default, ignoring client-supplied entries", () => {
    delete process.env.CEREBRO_WEB_TRUSTED_PROXY_HOPS;
    expect(clientIpFrom(forwarded("203.0.113.66, 198.51.100.7"))).toBe("198.51.100.7");
    expect(clientIpFrom(forwarded("198.51.100.7"))).toBe("198.51.100.7");
    expect(clientIpFrom(forwarded())).toBeNull();
  });

  it("honors CEREBRO_WEB_TRUSTED_PROXY_HOPS", () => {
    process.env.CEREBRO_WEB_TRUSTED_PROXY_HOPS = "2";
    expect(clientIpFrom(forwarded("203.0.113.66, 198.51.100.7, 10.0.0.2"))).toBe("198.51.100.7");
    expect(clientIpFrom(forwarded("10.0.0.2"))).toBeNull();
    process.env.CEREBRO_WEB_TRUSTED_PROXY_HOPS = "not-a-number";
    expect(clientIpFrom(forwarded("203.0.113.66, 198.51.100.7"))).toBe("198.51.100.7");
  });
});
