import { getCerebroProxyConfig } from "@/lib/cerebro-proxy";
import { isCerebroFixtureMode } from "@/lib/fixture-mode";

import { ssoBreakGlassEnabled, ssoRequired } from "./config";
import { fetchSsoConnections, fetchSsoPolicy, IdentityApiError } from "./identity-api";
import { DEFAULT_SSO_POLICY, type SSOConnection, type SSOPolicy } from "./types";

const POLICY_TTL_MS = 30_000;
const CONNECTIONS_TTL_MS = 30_000;

export type PolicyState = {
  policy: SSOPolicy;
  /** "unknown" means the Go API could not be read and no earlier answer is cached. */
  source: "api" | "default" | "stale" | "unknown";
};

type Cached<T> = { value: T; fetchedAt: number };

let policyCache: Cached<SSOPolicy> | null = null;
let policyInflight: Promise<PolicyState> | null = null;
let connectionsCache: Cached<SSOConnection[]> | null = null;
let connectionsInflight: Promise<SSOConnection[]> | null = null;

export const clearSsoPolicyCache = () => {
  policyCache = null;
  policyInflight = null;
  connectionsCache = null;
  connectionsInflight = null;
};

const loadPolicy = async (nowMs: number): Promise<PolicyState> => {
  if (isCerebroFixtureMode()) return { policy: DEFAULT_SSO_POLICY, source: "default" };
  try {
    const policy = await fetchSsoPolicy();
    policyCache = { value: policy, fetchedAt: nowMs };
    return { policy, source: "api" };
  } catch (error) {
    // A Go API without the identity routes has never enforced SSO.
    if (error instanceof IdentityApiError && error.status === 404) {
      policyCache = { value: DEFAULT_SSO_POLICY, fetchedAt: nowMs };
      return { policy: DEFAULT_SSO_POLICY, source: "default" };
    }
    if (policyCache) return { policy: policyCache.value, source: "stale" };
    return { policy: DEFAULT_SSO_POLICY, source: "unknown" };
  }
};

export const getSsoPolicyState = async (nowMs = Date.now()): Promise<PolicyState> => {
  if (policyCache && nowMs - policyCache.fetchedAt < POLICY_TTL_MS) {
    return { policy: policyCache.value, source: "api" };
  }
  if (!policyInflight) {
    policyInflight = loadPolicy(nowMs).finally(() => {
      policyInflight = null;
    });
  }
  return policyInflight;
};

/** True when the service credential is configured; without it the web server cannot reach the identity API. */
export const identityApiConfigured = () => isCerebroFixtureMode() || getCerebroProxyConfig().serverAuthConfigured;

export type EnforcementState = {
  /** SSO sessions are the only accepted browser identity. */
  enforced: boolean;
  /** Policy could not be read; callers fail closed for authentication. */
  unknown: boolean;
  breakGlass: boolean;
  policy: SSOPolicy;
};

export const getSsoEnforcement = async (nowMs = Date.now()): Promise<EnforcementState> => {
  const breakGlass = ssoBreakGlassEnabled();
  const required = ssoRequired();
  if (!identityApiConfigured()) {
    return { enforced: required, unknown: required, breakGlass, policy: DEFAULT_SSO_POLICY };
  }
  const state = await getSsoPolicyState(nowMs);
  if (breakGlass) return { enforced: false, unknown: false, breakGlass, policy: state.policy };
  if (state.source === "unknown") return { enforced: true, unknown: true, breakGlass, policy: state.policy };
  return { enforced: required || state.policy.enforced, unknown: false, breakGlass, policy: state.policy };
};

export const getCachedSsoConnections = async (nowMs = Date.now()): Promise<SSOConnection[]> => {
  if (connectionsCache && nowMs - connectionsCache.fetchedAt < CONNECTIONS_TTL_MS) return connectionsCache.value;
  if (!connectionsInflight) {
    connectionsInflight = fetchSsoConnections()
      .then((connections) => {
        connectionsCache = { value: connections, fetchedAt: nowMs };
        return connections;
      })
      .catch((error: unknown) => {
        if (connectionsCache) return connectionsCache.value;
        throw error;
      })
      .finally(() => {
        connectionsInflight = null;
      });
  }
  return connectionsInflight;
};
