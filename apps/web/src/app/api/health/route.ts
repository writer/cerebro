import { NextResponse } from "next/server";

import { identityRuntimeConfig } from "@/lib/identity";

export async function GET() {
  return NextResponse.json({
    status: "ready",
    checked_at: new Date().toISOString(),
    identity: identityRuntimeConfig(),
  });
}
