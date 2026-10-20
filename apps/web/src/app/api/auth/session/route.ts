import { NextRequest } from "next/server";

import { jsonNoStore } from "@/lib/sso/http";
import { currentUserForSsoSession, resolveSsoSessionFromHeaders } from "@/lib/sso/session";

export async function GET(request: NextRequest) {
  try {
    const resolved = await resolveSsoSessionFromHeaders(request.headers);
    if (!resolved) return jsonNoStore({ authenticated: false, user: null, expiresAt: null });
    return jsonNoStore({
      authenticated: true,
      user: await currentUserForSsoSession(resolved.session),
      expiresAt: resolved.session.expiresAt,
    });
  } catch {
    return jsonNoStore({ authenticated: false, user: null, expiresAt: null, error: "Session lookup is unavailable." }, 503);
  }
}
