import { NextResponse } from "next/server";

import { getCerebroProxyConfig } from "@/lib/cerebro-proxy";

export async function GET() {
  return NextResponse.json(getCerebroProxyConfig());
}
