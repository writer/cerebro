import { NextRequest } from "next/server";

import { beginSsoLogin } from "@/lib/sso/start";

/** Public sign-in start. Test sign-ins use /api/auth/sso/test, which requires an identity admin. */
export async function GET(request: NextRequest) {
  return beginSsoLogin(request, null);
}
