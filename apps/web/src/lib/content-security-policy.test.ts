import { describe, expect, it } from "vitest";

import {
  buildContentSecurityPolicy,
  generateCspNonce,
  nonceFromContentSecurityPolicy,
  scriptSrcDirective,
} from "./content-security-policy";

const directives = (policy: string) => policy.split(";").map((directive) => directive.trim());

describe("content security policy", () => {
  it("generates unpredictable base64 nonces", () => {
    const nonces = new Set(Array.from({ length: 32 }, () => generateCspNonce()));
    expect(nonces.size).toBe(32);
    for (const nonce of nonces) {
      expect(nonce).toMatch(/^[A-Za-z0-9+/]{22}==$/);
    }
  });

  it("allows scripts only through the request nonce in production", () => {
    const policy = buildContentSecurityPolicy({ nonce: "dGVzdA==" });
    const scriptSrc = directives(policy).find((directive) => directive.startsWith("script-src "));
    expect(scriptSrc).toBe("script-src 'self' 'nonce-dGVzdA==' 'strict-dynamic'");
    expect(policy).not.toContain("'unsafe-inline' 'nonce");
    expect(scriptSrc).not.toContain("'unsafe-inline'");
    expect(scriptSrc).not.toContain("'unsafe-eval'");
  });

  it("adds unsafe-eval but not unsafe-inline for development scripts", () => {
    const scriptSrc = scriptSrcDirective({ nonce: "dGVzdA==", development: true });
    expect(scriptSrc).toBe("script-src 'self' 'nonce-dGVzdA==' 'strict-dynamic' 'unsafe-eval'");
  });

  it("keeps the non-script directives", () => {
    const policy = directives(buildContentSecurityPolicy({ nonce: "dGVzdA==" }));
    expect(policy).toEqual(expect.arrayContaining([
      "default-src 'self'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "img-src 'self' data:",
      "style-src 'self' 'unsafe-inline'",
      "connect-src 'self'",
    ]));
  });

  it("rejects a nonce that could break out of the directive", () => {
    expect(() => scriptSrcDirective({ nonce: "abc' 'unsafe-inline" })).toThrow("base64");
  });

  it("reads the nonce back out of a policy", () => {
    const nonce = generateCspNonce();
    expect(nonceFromContentSecurityPolicy(buildContentSecurityPolicy({ nonce }))).toBe(nonce);
    expect(nonceFromContentSecurityPolicy("default-src 'self'; script-src 'self' 'unsafe-inline'")).toBeUndefined();
    expect(nonceFromContentSecurityPolicy(null)).toBeUndefined();
  });
});
