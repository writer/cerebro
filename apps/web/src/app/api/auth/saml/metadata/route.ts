import { NextRequest, NextResponse } from "next/server";

import { publicOrigin } from "@/lib/sso/config";
import { CONNECTION_ID_PATTERN } from "@/lib/sso/http";
import { fetchSsoConnection } from "@/lib/sso/identity-api";
import { samlServiceProviderMetadata } from "@/lib/sso/saml";
import type { SSOSamlConfig } from "@/lib/sso/types";

const NO_STORE = { "cache-control": "no-store" } as const;

/**
 * SP metadata. The entity ID and ACS URL are the same for every connection; `?connection=` only tailors the
 * advertised NameID format and signing preference to that connection's settings.
 */
export async function GET(request: NextRequest) {
  const origin = publicOrigin(request.url);
  if (!origin) {
    return NextResponse.json({ error: "CEREBRO_WEB_PUBLIC_URL is not configured." }, { status: 503, headers: NO_STORE });
  }
  const connectionId = request.nextUrl.searchParams.get("connection")?.trim() ?? "";
  let saml: SSOSamlConfig | undefined;
  if (connectionId) {
    if (!CONNECTION_ID_PATTERN.test(connectionId)) {
      return NextResponse.json({ error: "Not found." }, { status: 404, headers: NO_STORE });
    }
    try {
      const connection = await fetchSsoConnection(connectionId);
      if (connection?.protocol === "saml") saml = connection.saml;
    } catch {
      saml = undefined;
    }
  }
  return new NextResponse(samlServiceProviderMetadata(origin, saml), {
    status: 200,
    headers: {
      "content-type": "application/samlmetadata+xml; charset=utf-8",
      "cache-control": "public, max-age=300",
    },
  });
}
