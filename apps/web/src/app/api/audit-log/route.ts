import { NextRequest, NextResponse } from "next/server";

import { auditLogQueryFromSearchParams } from "@/lib/audit-log";
import {
  AUDIT_EVENT_CONTRACT_PATH,
  AuditLogReaderError,
  createHttpAuditLogReader,
} from "@/lib/audit-log-reader";
import { authorizationErrorResponse, authorizeCurrentUser } from "@/lib/authorization";
import { authHeadersFor, buildCerebroUrl } from "@/lib/cerebro-proxy";
import { isCerebroFixtureMode } from "@/lib/cerebro-fixtures";
import { resolveCurrentUserFromHeadersWithFallback } from "@/lib/identity";
import {
  headersWithTrace,
  responseHeadersWithTrace,
  startWebSpan,
} from "@/lib/observability";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  const span = startWebSpan(
    "audit.events.list",
    { component: "audit-events-api" },
    request.headers.get("traceparent"),
  );
  const currentUser = await resolveCurrentUserFromHeadersWithFallback(request.headers);
  if (!currentUser) {
    span.end("failed", { authorization_state: "identity_missing" });
    return NextResponse.json(
      {
        code: "identity_missing",
        error: "Current user identity is required.",
        permission: "cerebro:read",
      },
      {
        headers: responseHeadersWithTrace({ "cache-control": "private, no-store" }, span),
        status: 401,
      },
    );
  }
  const decision = authorizeCurrentUser(currentUser, "cerebro:read");
  if (!decision.allowed) {
    span.end("failed", { authorization_state: decision.code });
    return authorizationErrorResponse(decision);
  }

  if (isCerebroFixtureMode()) {
    span.end("completed", {
      audit_event_count: 0,
      audit_event_page_state: "complete",
    });
    return NextResponse.json({
      events: [],
      nextCursor: "",
      status: "complete",
      summary: {
        actions: [],
        averageDurationMs: null,
        denied: 0,
        failures: 0,
        p95DurationMs: null,
        services: [],
        total: 0,
      },
      window: null,
    }, {
      headers: responseHeadersWithTrace({ "cache-control": "private, no-store" }, span),
    });
  }

  const query = auditLogQueryFromSearchParams(request.nextUrl.searchParams);
  const reader = createHttpAuditLogReader({
    endpoint: buildCerebroUrl(AUDIT_EVENT_CONTRACT_PATH),
    headers: headersWithTrace(authHeadersFor(request), span),
  });

  try {
    const page = await reader.list(query, request.signal);
    span.end("completed", {
      audit_event_count: page.events.length,
      audit_event_page_state: page.status,
    });
    return NextResponse.json(page, {
      headers: responseHeadersWithTrace({ "cache-control": "private, no-store" }, span),
    });
  } catch (error) {
    const readerError = error instanceof AuditLogReaderError
      ? error
      : new AuditLogReaderError("Audit events are unavailable.");
    span.end("failed", {
      audit_event_error_status: readerError.status,
      audit_event_page_state: "unavailable",
    });
    return NextResponse.json(
      { error: readerError.message },
      {
        headers: responseHeadersWithTrace({ "cache-control": "private, no-store" }, span),
        status: readerError.status,
      },
    );
  }
}
