import { NextRequest, NextResponse } from "next/server";

import { identityHealthFromHeaders } from "@/lib/identity";

export async function GET(request: NextRequest) {
  return NextResponse.json(
    await identityHealthFromHeaders(request.headers),
    {
      headers: {
        "cache-control": "private, no-store",
      },
    },
  );
}
