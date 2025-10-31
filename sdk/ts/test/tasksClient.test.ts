import { beforeEach, describe, expect, it, vi } from "vitest";

import HttpClient from "../src/httpClient";
import {
  InMemoryTasksAdapter,
  TasksClient,
} from "../src/clients/tasks";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  // @ts-expect-error assign test fetch
  globalThis.fetch = fetchMock;
});

describe("TasksClient", () => {
  it("submits tasks via HTTP adapter", async () => {
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({ task_id: "task-1", status: "PENDING" }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({
          task_id: "task-1",
          status: "SUCCESS",
          successful: true,
          failed: false,
          result: { value: 1 },
          traceback: null,
          date_done: "2024-01-01T00:00:00Z",
        }),
      });

    const client = TasksClient.fromHttpClient(new HttpClient({ baseUrl: "https://api.example.com" }), {
      statusEndpoint: (taskId) => `/api/v1/tasks/${taskId}`,
      revokeEndpoint: (taskId) => `/api/v1/tasks/${taskId}/revoke`,
    });

    const submission = await client.enqueue("collect", []);
    expect(submission.status).toBe("PENDING");

    const status = await client.getStatus(submission.taskId);
    expect(status.successful).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("supports in-memory adapters", async () => {
    const adapter = new InMemoryTasksAdapter();
    const client = new TasksClient(adapter);

    const submission = await client.enqueue("report");
    const status = await client.getStatus(submission.taskId);
    expect(status.status).toBe("PENDING");

    await client.revoke(submission.taskId);
    const revoked = await client.getStatus(submission.taskId);
    expect(revoked.status).toBe("REVOKED");
  });
});
