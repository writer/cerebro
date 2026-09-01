// Content Security Policy for every document the web app serves.
//
// Scripts are allowed only when they carry the per-request nonce that the
// proxy generates. `'strict-dynamic'` lets those trusted scripts load the
// chunks they import without listing every URL, and it makes CSP3 browsers
// ignore `'self'` (kept as a fallback for older engines). There is no
// `'unsafe-inline'` in `script-src`: an injected inline script never runs, so
// an XSS bug cannot read the API key or session out of the page.

export const CSP_HEADER = "Content-Security-Policy";
export const NONCE_HEADER = "x-nonce";

const NONCE_BYTES = 16;

export const generateCspNonce = () => {
  const bytes = new Uint8Array(NONCE_BYTES);
  globalThis.crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
};

export type ContentSecurityPolicyOptions = {
  nonce: string;
  /** Development builds need `'unsafe-eval'` for React's server-stack reconstruction and Turbopack HMR. */
  development?: boolean;
};

export const scriptSrcDirective = ({ nonce, development = false }: ContentSecurityPolicyOptions) => {
  if (!/^[A-Za-z0-9+/=]+$/.test(nonce)) {
    throw new Error("CSP nonce must be base64");
  }
  const sources = ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'"];
  if (development) {
    sources.push("'unsafe-eval'");
  }
  return `script-src ${sources.join(" ")}`;
};

export const buildContentSecurityPolicy = (options: ContentSecurityPolicyOptions) =>
  [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "img-src 'self' data:",
    scriptSrcDirective(options),
    "style-src 'self' 'unsafe-inline'",
    "connect-src 'self'",
  ].join("; ");

/** Extracts the nonce from a policy's `script-src` directive, or `undefined` when there is none. */
export const nonceFromContentSecurityPolicy = (policy: string | null | undefined) => {
  const scriptSrc = (policy ?? "")
    .split(";")
    .map((directive) => directive.trim())
    .find((directive) => directive.startsWith("script-src "));
  return /'nonce-([A-Za-z0-9+/=]+)'/.exec(scriptSrc ?? "")?.[1];
};
