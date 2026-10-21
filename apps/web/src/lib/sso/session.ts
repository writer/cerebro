import type { CurrentUser, IdentityProvider } from "@/lib/identity";

import { readSessionToken, sessionTokenHash } from "./cookies";
import { lookupSsoSession } from "./identity-api";
import { getCachedSsoConnections } from "./policy";
import type { SSOConnection, SSOSession } from "./types";

// Bounds how long a Go-side revocation (admin revoke, SCIM deactivation, connection change) takes to reach
// every web replica, since only the replica handling a login or logout clears its own cache.
const SESSION_CACHE_TTL_MS = 5_000;
const SESSION_CACHE_MAX_ENTRIES = 5_000;

type CachedSession = { session: SSOSession | null; fetchedAt: number };

const sessionCache = new Map<string, CachedSession>();

export const clearSsoSessionCache = (tokenHash?: string) => {
  if (tokenHash) sessionCache.delete(tokenHash);
  else sessionCache.clear();
};

const sessionExpired = (session: SSOSession, nowMs: number) => {
  const expiresAt = Date.parse(session.expiresAt);
  return Number.isFinite(expiresAt) && expiresAt <= nowMs;
};

/** Looks up a session by token hash with a 15 s per-process cache. Revocations take effect within that window. */
export const lookupSsoSessionCached = async (tokenHash: string, nowMs = Date.now()): Promise<SSOSession | null> => {
  const cached = sessionCache.get(tokenHash);
  if (cached && nowMs - cached.fetchedAt < SESSION_CACHE_TTL_MS) {
    if (cached.session && sessionExpired(cached.session, nowMs)) return null;
    return cached.session;
  }
  const session = await lookupSsoSession(tokenHash);
  if (sessionCache.size >= SESSION_CACHE_MAX_ENTRIES) {
    for (const [key, entry] of sessionCache) {
      if (nowMs - entry.fetchedAt >= SESSION_CACHE_TTL_MS) sessionCache.delete(key);
    }
    if (sessionCache.size >= SESSION_CACHE_MAX_ENTRIES) sessionCache.clear();
  }
  sessionCache.set(tokenHash, { session, fetchedAt: nowMs });
  if (session && sessionExpired(session, nowMs)) return null;
  return session;
};

export type ResolvedSsoSession = {
  session: SSOSession;
  tokenHash: string;
};

/** Resolves the session cookie on a request. Returns null when there is no well-formed cookie or no live session. */
export const resolveSsoSessionFromHeaders = async (headers: Headers, nowMs = Date.now()): Promise<ResolvedSsoSession | null> => {
  const token = readSessionToken(headers);
  if (!token) return null;
  const tokenHash = sessionTokenHash(token);
  const session = await lookupSsoSessionCached(tokenHash, nowMs);
  return session ? { session, tokenHash } : null;
};

const OKTA_HOST = /(^|\.)(okta|oktapreview|okta-emea|okta-gov)\.com$/i;

export const providerForConnection = (connection: SSOConnection | undefined): IdentityProvider => {
  if (!connection) return "oidc";
  if (connection.protocol === "saml") return "saml";
  try {
    if (connection.oidc?.issuer && OKTA_HOST.test(new URL(connection.oidc.issuer).hostname)) return "okta";
  } catch {
    // Fall through to the generic provider.
  }
  return "oidc";
};

const cleanList = (values: unknown) =>
  Array.isArray(values)
    ? Array.from(new Set(values.filter((value): value is string => typeof value === "string").map((value) => value.trim()).filter(Boolean)))
    : [];

const initialsFor = (name: string, email: string) => {
  const parts = name.split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return `${parts[0][0]}${parts[parts.length - 1][0]}`.toUpperCase();
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (email.split("@")[0] || "?").slice(0, 2).toUpperCase();
};

export const currentUserFromSsoSession = (session: SSOSession, provider: IdentityProvider): CurrentUser => {
  const email = (session.email ?? "").trim();
  const name = (session.name ?? "").trim();
  const subject = (session.subject ?? "").trim();
  const displayName = name || email || subject;
  const groups = cleanList(session.groups);
  const roles = cleanList(session.roles);
  return {
    actorId: subject || email,
    actorLabel: email || displayName,
    confidence: "signature-verified",
    displayName,
    initials: initialsFor(name, email),
    ...(email ? { email, username: email } : {}),
    ...(subject ? { subject } : {}),
    provider,
    source: "sso-session",
    entitlements: {
      ...(groups.length ? { groups } : {}),
      roles,
    },
    evidence: {
      inferred: ["sso-session"],
      jwt: { expiresAt: session.expiresAt },
    },
  };
};

export const currentUserForSsoSession = async (session: SSOSession): Promise<CurrentUser> => {
  let connection: SSOConnection | undefined;
  try {
    connection = (await getCachedSsoConnections()).find((candidate) => candidate.id === session.connectionId);
  } catch {
    connection = undefined;
  }
  return currentUserFromSsoSession(session, providerForConnection(connection));
};
