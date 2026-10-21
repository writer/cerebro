const MAX_RETURN_TO_LENGTH = 2048;
const SENTINEL_ORIGIN = "https://return-to.invalid";

/**
 * Accepts only same-origin relative paths. Anything that a browser could resolve to another origin
 * (scheme-relative `//host`, backslash tricks, schemes, control characters) collapses to "/".
 */
export const sanitizeReturnTo = (value: unknown, fallback = "/"): string => {
  if (typeof value !== "string") return fallback;
  if (value.length === 0 || value.length > MAX_RETURN_TO_LENGTH) return fallback;
  if (!value.startsWith("/")) return fallback;
  if (value.startsWith("//")) return fallback;
  if (value.includes("\\")) return fallback;
  if (/[\u0000-\u001F\u007F\s]/.test(value)) return fallback;
  let resolved: URL;
  try {
    resolved = new URL(value, SENTINEL_ORIGIN);
  } catch {
    return fallback;
  }
  if (resolved.origin !== SENTINEL_ORIGIN) return fallback;
  const path = `${resolved.pathname}${resolved.search}${resolved.hash}`;
  if (path.startsWith("//")) return fallback;
  if (resolved.pathname === "/login" || resolved.pathname.startsWith("/api/auth/")) return fallback;
  return path;
};
