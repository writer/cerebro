import { describe, expect, it, vi } from "vitest";

import { AgentReviewExporter } from "../src/agents";
import { AgentsClient } from "../src/clients/agents";
import { ReviewTaskRecord } from "../src/types";

describe("AgentReviewExporter", () => {
  it("exports tasks with comments and history", async () => {
    const task: ReviewTaskRecord = {
      taskId: "task-1",
      sessionId: "session-1",
      orgId: "org-1",
      status: "pending",
      title: "Review",
      summary: null,
      payload: {},
      promotionTarget: null,
      priority: null,
      dueAt: null,
      escalatedTo: null,
      notificationChannel: null,
      ticketReference: null,
      createdBy: "user",
      createdAt: new Date(),
      resolvedBy: null,
      resolvedAt: null,
      resolutionNotes: null,
    };

    const listReviewTasks = vi.fn().mockResolvedValue([task]);
    const listReviewTaskComments = vi.fn().mockResolvedValue([
      {
        commentId: "comment-1",
        taskId: "task-1",
        author: "user",
        content: "note",
        createdAt: new Date(),
        updatedAt: null,
        metadata: {},
      },
    ]);
    const listReviewTaskHistory = vi.fn().mockResolvedValue([
      {
        historyId: "hist-1",
        taskId: "task-1",
        changedBy: "user",
        changeType: "status_change",
        fieldName: "status",
        oldValue: { status: "pending" },
        newValue: { status: "resolved" },
        createdAt: new Date(),
        metadata: {},
      },
    ]);

    const fakeClient = {
      listReviewTasks,
      listReviewTaskComments,
      listReviewTaskHistory,
    } as unknown as AgentsClient;

    const exporter = new AgentReviewExporter(fakeClient);
    const exported = await exporter.exportTasks("org-1", { status: "pending", limit: 10 });

    expect(exported).toHaveLength(1);
    expect(exported[0].comments).toHaveLength(1);
    expect(exported[0].history).toHaveLength(1);
    expect(listReviewTasks).toHaveBeenCalledWith({ status: "pending", limit: 10 });
  });

  it("omits comments and history when disabled", async () => {
    const task: ReviewTaskRecord = {
      taskId: "task-2",
      sessionId: "session-2",
      orgId: "org-1",
      status: "pending",
      title: "Review",
      summary: null,
      payload: {},
      promotionTarget: null,
      priority: null,
      dueAt: null,
      escalatedTo: null,
      notificationChannel: null,
      ticketReference: null,
      createdBy: "user",
      createdAt: new Date(),
      resolvedBy: null,
      resolvedAt: null,
      resolutionNotes: null,
    };

    const fakeClient = {
      listReviewTasks: vi.fn().mockResolvedValue([task]),
      listReviewTaskComments: vi.fn(),
      listReviewTaskHistory: vi.fn(),
    } as unknown as AgentsClient;

    const exporter = new AgentReviewExporter(fakeClient);
    const exported = await exporter.exportTasks("org-1", {
      includeComments: false,
      includeHistory: false,
    });

    expect(exported[0].comments).toHaveLength(0);
    expect(exported[0].history).toHaveLength(0);
    expect(fakeClient.listReviewTaskComments).not.toHaveBeenCalled();
    expect(fakeClient.listReviewTaskHistory).not.toHaveBeenCalled();
  });
});
