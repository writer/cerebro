/**
 * Last SSO enforcement decision made by this process. Request authorization is synchronous, but every route
 * resolves the current user (which evaluates enforcement) before authorizing, so this reflects the decision
 * for the current request. Kept dependency-free so authorization code can read it without importing the
 * identity API client.
 */
let lastEnforced = false;

export const noteSsoEnforcement = (enforced: boolean) => {
  lastEnforced = enforced;
};

export const ssoEnforcementActive = () => lastEnforced;
