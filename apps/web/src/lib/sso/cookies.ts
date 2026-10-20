import { createHash, randomBytes } from "crypto";
import type { NextResponse } from "next/server";

import { cookiesSecure, sessionCookieName, txCookieName } from "./config";
import { TX_TTL_SECONDS } from "./tx";

const SESSION_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export const generateSessionToken = () => randomBytes(32).toString("base64url");

export const isWellFormedSessionToken = (token: string | null | undefined): token is string =>
  typeof token === "string" && SESSION_TOKEN_PATTERN.test(token);

/** Lowercase hex sha256 of the raw cookie token; the only form Go ever sees. */
export const sessionTokenHash = (token: string) => createHash("sha256").update(token, "utf8").digest("hex");

export const readCookie = (headers: Headers, name: string): string | null => {
  const header = headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() !== name) continue;
    const value = part.slice(index + 1).trim();
    try {
      return decodeURIComponent(value);
    } catch {
      return null;
    }
  }
  return null;
};

export const readSessionToken = (headers: Headers) => {
  const token = readCookie(headers, sessionCookieName());
  return isWellFormedSessionToken(token) ? token : null;
};

export const readTxCookie = (headers: Headers) => readCookie(headers, txCookieName());

export const setSessionCookie = (response: NextResponse, token: string, maxAgeSeconds: number) => {
  response.cookies.set({
    name: sessionCookieName(),
    value: token,
    httpOnly: true,
    secure: cookiesSecure(),
    sameSite: "lax",
    path: "/",
    maxAge: Math.max(60, Math.floor(maxAgeSeconds)),
  });
};

export const clearSessionCookie = (response: NextResponse) => {
  response.cookies.set({
    name: sessionCookieName(),
    value: "",
    httpOnly: true,
    secure: cookiesSecure(),
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
};

/**
 * The SAML HTTP-POST binding is a cross-site form POST, so the transaction cookie must be SameSite=None
 * (which browsers only honor with Secure). Plain-http development falls back to Lax.
 */
const txSameSite = () => (cookiesSecure() ? "none" : "lax");

export const setTxCookie = (response: NextResponse, sealed: string) => {
  response.cookies.set({
    name: txCookieName(),
    value: sealed,
    httpOnly: true,
    secure: cookiesSecure(),
    sameSite: txSameSite(),
    path: "/",
    maxAge: TX_TTL_SECONDS,
  });
};

export const clearTxCookie = (response: NextResponse) => {
  response.cookies.set({
    name: txCookieName(),
    value: "",
    httpOnly: true,
    secure: cookiesSecure(),
    sameSite: txSameSite(),
    path: "/",
    maxAge: 0,
  });
};
