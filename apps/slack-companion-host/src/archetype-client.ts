import {
  parseArchetypeDailyDigest,
  parseArchetypeFindingActionExecution,
  parseArchetypeFindingActionIntent,
  type ArchetypeDailyDigestV1,
  type ArchetypeFindingActionExecutionV1,
  type ArchetypeFindingActionIntentV1,
} from "@writer/cerebro-slack-companion";

const MAX_RESPONSE_BYTES = 2_000_000;
const MAX_OKTA_GROUPS = 200;

export interface ArchetypeWorkspaceClientOptions {
  allowedEmailDomains: ReadonlySet<string>;
  archetypeBaseUrl: string;
  fetchImpl?: typeof fetch;
  oktaApiToken: string;
  oktaDomain: string;
  timeoutMs: number;
}

export interface SlackUserLookupPort {
  users: {
    info(input: { user: string }): Promise<{
      ok?: boolean;
      user?: {
        deleted?: boolean;
        id?: string;
        is_bot?: boolean;
        profile?: {
          display_name?: string;
          email?: string;
          real_name?: string;
        };
        team_id?: string;
      };
    }>;
  };
}

export interface VerifiedArchetypeIdentity {
  readonly displayName: string;
  readonly email: string;
  readonly groups: readonly string[];
  readonly login: string;
  readonly oktaUserId: string;
  readonly slackTeamId: string;
  readonly slackUserId: string;
}

export class ArchetypeWorkspaceClientError extends Error {
  constructor(
    message: string,
    readonly state:
      | "identity_unavailable"
      | "identity_unverified"
      | "source_rejected"
      | "source_unavailable",
  ) {
    super(message);
    this.name = "ArchetypeWorkspaceClientError";
  }
}

export class ArchetypeWorkspaceClient {
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: ArchetypeWorkspaceClientOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async resolveIdentity(input: {
    slack: SlackUserLookupPort;
    teamId: string;
    userId: string;
  }): Promise<VerifiedArchetypeIdentity> {
    const slackUser = await input.slack.users.info({ user: input.userId });
    const user = slackUser.user;
    if (
      slackUser.ok === false
      || !user
      || user.id !== input.userId
      || user.team_id !== input.teamId
      || user.deleted === true
      || user.is_bot === true
    ) {
      throw new ArchetypeWorkspaceClientError(
        "The Slack account could not be verified for this workspace.",
        "identity_unverified",
      );
    }
    const slackEmail = normalizedEmail(user.profile?.email);
    if (!slackEmail || !this.allowedEmail(slackEmail)) {
      throw new ArchetypeWorkspaceClientError(
        "The Slack account does not have an allowed work email.",
        "identity_unverified",
      );
    }
    const oktaUser = await this.oktaRequest(
      `/api/v1/users/${encodeURIComponent(slackEmail)}`,
    );
    const identity = parseOktaUser(oktaUser);
    if (
      identity.status !== "ACTIVE"
      || identity.email.toLowerCase() !== slackEmail
    ) {
      throw new ArchetypeWorkspaceClientError(
        "The Slack account does not match an active Okta user.",
        "identity_unverified",
      );
    }
    const groupResult = await this.oktaRequest(
      `/api/v1/users/${encodeURIComponent(identity.id)}/groups`,
    );
    const groups = parseOktaGroups(groupResult);
    return Object.freeze({
      displayName: identity.displayName,
      email: identity.email.toLowerCase(),
      groups,
      login: identity.login,
      oktaUserId: identity.id,
      slackTeamId: input.teamId,
      slackUserId: input.userId,
    });
  }

  async dailyDigest(
    identity: VerifiedArchetypeIdentity,
  ): Promise<ArchetypeDailyDigestV1> {
    const digest = parseArchetypeDailyDigest(
      await this.archetypeRequest("/api/v1/workspace/digest", identity),
    );
    if (digest.actor_id.toLowerCase() !== identity.email) {
      throw new ArchetypeWorkspaceClientError(
        "Archetype returned work for a different signed-in user.",
        "source_rejected",
      );
    }
    return digest;
  }

  async createStartWorkIntent(
    identity: VerifiedArchetypeIdentity,
    findingRef: string,
  ): Promise<ArchetypeFindingActionIntentV1> {
    return parseArchetypeFindingActionIntent(
      await this.archetypeRequest(
        "/api/v1/workspace/action-intents",
        identity,
        {
          body: JSON.stringify({
            action: "start_work",
            finding_ref: findingRef,
          }),
          method: "POST",
        },
      ),
    );
  }

  async executeStartWorkIntent(
    identity: VerifiedArchetypeIdentity,
    intentId: string,
  ): Promise<ArchetypeFindingActionExecutionV1> {
    return parseArchetypeFindingActionExecution(
      await this.archetypeRequest(
        `/api/v1/workspace/action-intents/${encodeURIComponent(intentId)}/execute`,
        identity,
        { body: "{}", method: "POST" },
      ),
    );
  }

  private async archetypeRequest(
    path: string,
    identity: VerifiedArchetypeIdentity,
    init: { body?: string; method?: "GET" | "POST" } = {},
  ): Promise<unknown> {
    const headers = new Headers({
      accept: "application/json",
      "content-type": "application/json",
      "x-okta-email": identityHeader(identity.email, "Okta email"),
      "x-okta-name": safeIdentityHeader(identity.displayName, identity.email),
      "x-okta-user": identityHeader(identity.login, "Okta login"),
    });
    if (identity.groups.length > 0) {
      headers.set(
        "x-archetype-groups",
        identityHeader(identity.groups.join(","), "Okta groups", 6_000),
      );
    }
    return this.request(
      new URL(path, `${this.options.archetypeBaseUrl}/`),
      {
        body: init.body,
        headers,
        method: init.method ?? "GET",
      },
      "archetype",
    );
  }

  private async oktaRequest(path: string): Promise<unknown> {
    return this.request(
      new URL(path, `${this.options.oktaDomain}/`),
      {
        headers: {
          accept: "application/json",
          authorization: `SSWS ${this.options.oktaApiToken}`,
        },
        method: "GET",
      },
      "okta",
    );
  }

  private async request(
    url: URL,
    init: RequestInit,
    source: "archetype" | "okta",
  ): Promise<unknown> {
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        ...init,
        redirect: "error",
        signal: AbortSignal.timeout(this.options.timeoutMs),
      });
    } catch {
      throw new ArchetypeWorkspaceClientError(
        `${source === "okta" ? "Okta" : "Archetype"} is unavailable.`,
        source === "okta" ? "identity_unavailable" : "source_unavailable",
      );
    }
    if (!response.ok) {
      throw new ArchetypeWorkspaceClientError(
        `${source === "okta" ? "Okta" : "Archetype"} rejected the request.`,
        response.status >= 500
          ? source === "okta"
            ? "identity_unavailable"
            : "source_unavailable"
          : source === "okta"
            ? "identity_unverified"
            : "source_rejected",
      );
    }
    const length = Number(response.headers.get("content-length"));
    if (Number.isFinite(length) && length > MAX_RESPONSE_BYTES) {
      throw new ArchetypeWorkspaceClientError(
        `${source === "okta" ? "Okta" : "Archetype"} returned an oversized response.`,
        source === "okta" ? "identity_unavailable" : "source_unavailable",
      );
    }
    const body = await response.text();
    if (Buffer.byteLength(body, "utf8") > MAX_RESPONSE_BYTES) {
      throw new ArchetypeWorkspaceClientError(
        `${source === "okta" ? "Okta" : "Archetype"} returned an oversized response.`,
        source === "okta" ? "identity_unavailable" : "source_unavailable",
      );
    }
    try {
      return JSON.parse(body) as unknown;
    } catch {
      throw new ArchetypeWorkspaceClientError(
        `${source === "okta" ? "Okta" : "Archetype"} returned an invalid response.`,
        source === "okta" ? "identity_unavailable" : "source_unavailable",
      );
    }
  }

  private allowedEmail(value: string): boolean {
    const domain = value.slice(value.lastIndexOf("@") + 1);
    return this.options.allowedEmailDomains.has(domain);
  }
}

function parseOktaUser(value: unknown): {
  displayName: string;
  email: string;
  id: string;
  login: string;
  status: string;
} {
  const user = record(value, "Okta user");
  const profile = record(user.profile, "Okta user profile");
  const firstName = optionalText(profile.firstName, 100);
  const lastName = optionalText(profile.lastName, 100);
  const email = normalizedEmail(profile.email);
  const login = normalizedEmail(profile.login);
  if (!email || !login) {
    throw new ArchetypeWorkspaceClientError(
      "Okta returned a user without a verified email.",
      "identity_unverified",
    );
  }
  return {
    displayName: [firstName, lastName].filter(Boolean).join(" ") || email,
    email,
    id: requiredText(user.id, "Okta user id", 200),
    login,
    status: requiredText(user.status, "Okta user status", 50),
  };
}

function parseOktaGroups(value: unknown): readonly string[] {
  if (
    !Array.isArray(value)
    || value.length > MAX_OKTA_GROUPS
    || Object.getPrototypeOf(value) !== Array.prototype
  ) {
    throw new ArchetypeWorkspaceClientError(
      "Okta returned an invalid group list.",
      "identity_unavailable",
    );
  }
  const groups = value.flatMap((item, index) => {
    const group = record(item, `Okta group ${index + 1}`);
    const profile = record(group.profile, `Okta group ${index + 1} profile`);
    const name = requiredText(
      profile.name,
      `Okta group ${index + 1} name`,
      200,
    );
    return /^[A-Za-z0-9_.:-]+$/.test(name) ? [name] : [];
  });
  return Object.freeze([...new Set(groups)].sort());
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (
    value === null
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new ArchetypeWorkspaceClientError(
      `${field} is invalid.`,
      "identity_unavailable",
    );
  }
  return value as Record<string, unknown>;
}

function normalizedEmail(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim().toLowerCase();
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalized)
    && normalized.length <= 320
    ? normalized
    : undefined;
}

function optionalText(value: unknown, maximum: number): string | undefined {
  if (value === undefined || value === null || typeof value !== "string") {
    return undefined;
  }
  const normalized = value.trim();
  return normalized && normalized.length <= maximum ? normalized : undefined;
}

function requiredText(
  value: unknown,
  field: string,
  maximum: number,
): string {
  const normalized = optionalText(value, maximum);
  if (!normalized) {
    throw new ArchetypeWorkspaceClientError(
      `${field} is invalid.`,
      "identity_unavailable",
    );
  }
  return normalized;
}

function identityHeader(
  value: string,
  field: string,
  maximum = 500,
): string {
  if (
    value.length === 0
    || value.length > maximum
    || /[^\u0020-\u007e]/.test(value)
  ) {
    throw new ArchetypeWorkspaceClientError(
      `${field} cannot be represented as a trusted identity header.`,
      "identity_unverified",
    );
  }
  return value;
}

function safeIdentityHeader(value: string, fallback: string): string {
  return value.length <= 500 && /^[\u0020-\u007e]+$/.test(value)
    ? value
    : identityHeader(fallback, "Okta display name");
}
