import { getCerebroProxyConfig } from "@/lib/cerebro-proxy";
import { isCerebroFixtureMode } from "@/lib/fixture-mode";

import { ssoBreakGlassEnabled, ssoRequired } from "./config";
import { noteSsoEnforcement } from "./enforcement-signal";
import { fetchSsoConnections, fetchSsoPolicy, IdentityApiError } from "./identity-api";
import { DEFAULT_SSO_POLICY, type SSOConnection, type SSOPolicy } from "./types";

const POLICY_TTL_MS = 30_000;
const CONNECTIONS_TTL_MS = 30_000;

export type PolicyState = {
  policy: SSOPolicy;
  /**
   * "unknown" means the Go API could not be read and the last answer cannot be trusted to be non-enforcing.
   * "unavailable" means the Go API has no identity SSO store, so SSO was never configured there.
   */
  source: "api" | "default" | "stale" | "unknown" | "unavailable";
};

type Cached<T> = { value: T; fetchedAt: number };

let policyCache: (Cached<SSOPolicy> & { source: "api" | "unavailable" }) | null = null;
let policyInflight: Promise<PolicyState> | null = null;
let connectionsCache: Cached<SSOConnection[]> | null = null;
let connectionsInflight: Promise<SSOConnection[]> | null = null;
// Survives cache invalidation on purpose: once this replica has seen SSO enforced, a later failure to read
// the policy (including the store disappearing) must not quietly re-enable header identity.
let enforcedSeen = false;

export const clearSsoPolicyCache = () => {
  policyCache = null;
  policyInflight = null;
  connectionsCache = null;
  connectionsInflight = null;
};

export const resetSsoPolicyStateForTests = () => {
  clearSsoPolicyCache();
  enforcedSeen = false;
};

const IDENTITY_SSO_UNAVAILABLE = "identity_sso_unavailable";

const loadPolicy = async (nowMs: number): Promise<PolicyState> => {
  if (isCerebroFixtureMode()) return { policy: DEFAULT_SSO_POLICY, source: "default" };
  try {
    const policy = await fetchSsoPolicy();
    if (policy.enforced) enforcedSeen = true;
    policyCache = { value: policy, fetchedAt: nowMs, source: "api" };
    return { policy, source: "api" };
  } catch (error) {
    if (enforcedSeen) return { policy: policyCache?.value ?? DEFAULT_SSO_POLICY, source: "unknown" };
    // The Go API reports that it has no identity SSO store (or predates the identity routes): SSO was never
    // configured there, so header identity keeps working unless the deployment requires SSO.
    if (error instanceof IdentityApiError && error.status === 404 && (!error.code || error.code === IDENTITY_SSO_UNAVAILABLE)) {
      policyCache = { value: DEFAULT_SSO_POLICY, fetchedAt: nowMs, source: "unavailable" };
      return { policy: DEFAULT_SSO_POLICY, source: "unavailable" };
    }
    // An expired cached policy is only trusted while it still enforces; a stale "off" could hide a policy that
    // was turned on since, so it is treated as unknown (fail closed).
    if (policyCache?.value.enforced) return { policy: policyCache.value, source: "stale" };
    return { policy: policyCache?.value ?? DEFAULT_SSO_POLICY, source: "unknown" };
  }
};

export const getSsoPolicyState = async (nowMs = Date.now()): Promise<PolicyState> => {
  if (policyCache && nowMs - policyCache.fetchedAt < POLICY_TTL_MS) {
    return { policy: policyCache.value, source: policyCache.source };
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
  /** No service credential, or the Go API has no identity SSO store: SSO cannot be used at all. */
  unavailable: boolean;
  breakGlass: boolean;
  policy: SSOPolicy;
};

const decideEnforcement = async (nowMs: number): Promise<EnforcementState> => {
  const breakGlass = ssoBreakGlassEnabled();
  const required = ssoRequired();
  if (!identityApiConfigured()) {
    return { enforced: required, unknown: required, unavailable: true, breakGlass, policy: DEFAULT_SSO_POLICY };
  }
  const state = await getSsoPolicyState(nowMs);
  if (state.source === "unavailable") {
    return { enforced: required, unknown: required, unavailable: true, breakGlass, policy: state.policy };
  }
  if (breakGlass) return { enforced: false, unknown: false, unavailable: false, breakGlass, policy: state.policy };
  if (state.source === "unknown") return { enforced: true, unknown: true, unavailable: false, breakGlass, policy: state.policy };
  return { enforced: required || state.policy.enforced, unknown: false, unavailable: false, breakGlass, policy: state.policy };
};

export const getSsoEnforcement = async (nowMs = Date.now()): Promise<EnforcementState> => {
  const state = await decideEnforcement(nowMs);
  noteSsoEnforcement(state.enforced);
  return state;
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
