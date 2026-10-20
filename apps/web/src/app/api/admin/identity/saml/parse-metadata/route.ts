import { NextRequest } from "next/server";

import { authorizeIdentityRequest } from "@/lib/sso/admin-auth";
import { jsonNoStore } from "@/lib/sso/http";
import { UnsafeUrlError } from "@/lib/sso/safe-fetch";
import { fetchIdpMetadata, MAX_METADATA_BYTES, MetadataError, parseIdpMetadata } from "@/lib/sso/saml-metadata";

export async function POST(request: NextRequest) {
  const authorization = await authorizeIdentityRequest(request, "identity:admin");
  if (!authorization.ok) return authorization.response;
  const raw = await request.text();
  if (Buffer.byteLength(raw, "utf8") > MAX_METADATA_BYTES + 1024) return jsonNoStore({ error: "Request body is too large." }, 413);
  let body: { xml?: unknown; url?: unknown };
  try {
    body = JSON.parse(raw) as typeof body;
  } catch {
    return jsonNoStore({ error: "Request body must be JSON." }, 400);
  }
  try {
    let xml: string;
    if (typeof body?.xml === "string" && body.xml.trim()) {
      xml = body.xml;
    } else if (typeof body?.url === "string" && body.url.trim()) {
      xml = await fetchIdpMetadata(body.url.trim());
    } else {
      return jsonNoStore({ error: "Provide metadata xml or an https url." }, 400);
    }
    return jsonNoStore(await parseIdpMetadata(xml));
  } catch (error) {
    if (error instanceof MetadataError || error instanceof UnsafeUrlError) {
      return jsonNoStore({ error: error.message }, 422);
    }
    return jsonNoStore({ error: "Metadata could not be retrieved." }, 502);
  }
}
