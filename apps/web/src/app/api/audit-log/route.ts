import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export function GET(request: NextRequest) {
  const target = new URL(request.url);
  target.pathname = "/api/cerebro/grc/audit-log";
  return NextResponse.redirect(target, 307);
}
