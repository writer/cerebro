import { NextResponse } from "next/server";

import { askAgentRuntimeConfig } from "@/lib/ask-agent-config";
import { askAgentReadiness } from "@/lib/ask-agent-status";

export async function GET() {
  return NextResponse.json(askAgentReadiness({ canRunAgent: askAgentRuntimeConfig().canRunAgent }));
}
