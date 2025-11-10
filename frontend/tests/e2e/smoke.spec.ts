import { test, expect } from "@playwright/test";

const API_PREFIX = "http://localhost:8000/api/v1";

const queueSummary = {
  pending: {
    total: 5,
    unassigned: 2,
    overdue: 1,
    next_due: "2025-01-15T10:30:00Z",
    oldest_created: "2025-01-10T08:00:00Z",
  },
  status_counts: [
    { status: "pending_review", count: 3, unassigned: 1, overdue: 1 },
    { status: "in_progress", count: 1, unassigned: 0, overdue: 0 },
    { status: "awaiting_context", count: 1, unassigned: 1, overdue: 0 },
  ],
  priority_breakdown: [
    { priority: "P1", count: 1 },
    { priority: "P2", count: 2 },
    { priority: "P3", count: 2 },
  ],
  generated_at: "2025-01-15T12:00:00Z",
};

const integrationOverview = [
  {
    integration: "github",
    scope: "prod",
    status: "fresh",
    age_seconds: 3600,
    age_human: "1 hour ago",
    confidence: "high",
  },
];

const reviewTasks = [
  {
    id: "task-1",
    session_id: "session-1",
    org_id: "org-1",
    status: "pending",
    title: "Investigate unusual login",
    summary: "Risky login detected from unfamiliar device",
    payload: { actor: "user-123", severity: "high" },
    priority: "P1",
    promotion_target: null,
    due_at: null,
    escalated_to: null,
    notification_channel: null,
    ticket_reference: null,
    created_by: "alex@cerebro.security",
    created_at: "2025-01-15T09:00:00Z",
    resolved_by: null,
    resolved_at: null,
    resolution_notes: null,
  },
];

test("review dashboard renders queue health", async ({ page }) => {
  await page.route(`${API_PREFIX}/*`, (route) => {
    const url = new URL(route.request().url());
    const { pathname } = url;

    if (pathname.endsWith("/agents/review-tasks/summary")) {
      return void route.fulfill({ json: queueSummary, status: 200 });
    }

    if (pathname.endsWith("/agents/review-tasks")) {
      return void route.fulfill({ json: reviewTasks, status: 200 });
    }

    if (pathname.endsWith("/agents/review-tasks/notifications")) {
      return void route.fulfill({ json: [], status: 200 });
    }

    if (pathname.endsWith("/integrations/admin/overview")) {
      return void route.fulfill({ json: integrationOverview, status: 200 });
    }

    if (/\/agents\/sessions\/[^/]+$/.test(pathname)) {
      return void route.fulfill({
        json: {
          session: {
            session_id: "session-1",
            org_id: "org-1",
            agent_type: "review-assistant",
            title: "Review Session",
            created_at: "2025-01-15T08:30:00Z",
            created_by: "analyst@cerebro.security",
            status: "active",
            context: { region: "us-east-1" },
          },
          messages: [
            {
              message_id: "msg-1",
              role: "system",
              content: "Start review",
              timestamp: "2025-01-15T08:30:01Z",
              metadata: {},
            },
          ],
          message_count: 1,
          tool_invocations: [],
          metrics: {},
        },
        status: 200,
      });
    }

    if (/\/agents\/sessions\/[^/]+\/memory$/.test(pathname)) {
      return void route.fulfill({ json: [], status: 200 });
    }

    if (/\/agents\/sessions\/[^/]+\/memory\/stats$/.test(pathname)) {
      return void route.fulfill({
        json: {
          total_entries: 0,
          recent_entries: 0,
          presented_entries: 0,
          average_decay: 0,
          token_total: 0,
          role_distribution: {},
          scope_distribution: {},
          top_memories: [],
        },
        status: 200,
      });
    }

    if (/\/analytics\/summary$/.test(pathname)) {
      return void route.fulfill({ json: [], status: 200 });
    }

    if (/\/analytics$/.test(pathname)) {
      return void route.fulfill({ json: [], status: 200 });
    }

    return void route.fulfill({ json: [], status: 200 });
  });

  await page.goto("/agents/review");
  await page.waitForLoadState("networkidle");

  await expect(page.getByRole("heading", { name: "Queue health overview" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Review queue" })).toBeVisible();
});
