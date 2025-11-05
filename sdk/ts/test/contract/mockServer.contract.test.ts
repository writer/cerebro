import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { CerebroSDK } from "../../src/sdk";
import { parseAgentEventStream } from "../../src/agents/streaming";

const fixturesDir = path.resolve(__dirname, "../fixtures");

describe("mock server harness", () => {
  let server: ReturnType<typeof createServer>;
  let baseUrl: string;

  beforeAll(async () => {
    server = createServer(async (req, res) => {
      const requestUrl = new URL(req.url ?? "", `http://${req.headers.host ?? "127.0.0.1"}`);
      if (req.method === "GET" && requestUrl.pathname === "/api/v1/agents/review-tasks") {
        await respondWithJson(res, "agents/review-tasks.json");
        return;
      }

      if (req.method === "GET" && requestUrl.pathname === "/api/v1/integrations/coverage") {
        await respondWithJson(res, "integrations/coverage.json");
        return;
      }

      if (req.method === "POST" && requestUrl.pathname.startsWith("/api/v1/agents/sessions/")) {
        const body = await readBody(req);
        const wantsStream = body.stream === true;

        if (wantsStream) {
          res.writeHead(200, {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
          });
          res.write("event: message\n");
          res.write("data: {\"message_id\":\"msg-1\",\"role\":\"assistant\",\"content\":\"Hello\"}\n\n");
          res.write("event: status\n");
          res.write("data: {\"status\":\"completed\"}\n\n");
          res.end();
          return;
        }

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            status: "ack",
            message_id: "msg-ack",
            created_at: new Date().toISOString(),
          }),
        );
        return;
      }

      res.statusCode = 404;
      res.end();
    });

    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        if (typeof address === "object" && address) {
          baseUrl = `http://${address.address}:${address.port}`;
        } else {
          throw new Error("Failed to start mock server");
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  });

  it("performs end-to-end flows against mock server", async () => {
    const sdk = new CerebroSDK({ baseUrl, apiKey: "test-key" });

    const tasks = await sdk.agents.listReviewTasks({ limit: 10 });
    expect(tasks).toHaveLength(1);
    expect(tasks[0]?.title).toBe("Check deployment");
    expect(tasks[0]?.dueAt?.toISOString()).toBe("2024-10-25T10:00:00.000Z");

    const [coverage] = await sdk.integrations.getCoverage({ integration: "github" });
    expect(coverage?.integration).toBe("github");
    expect(coverage?.coverageRatio).toBeCloseTo(0.8);

    const streamResult = await sdk.agents.sendSessionMessage("session-123", {
      content: "Hi",
      stream: true,
    });

    expect(streamResult.kind).toBe("stream");
    const stream = streamResult.kind === "stream" ? streamResult.stream : undefined;
    if (!stream) throw new Error("Expected stream handle");

    const events = [];
    for await (const evt of parseAgentEventStream(stream)) {
      events.push(evt);
    }

    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({ type: "message" });
    expect(events[0].type === "message" && events[0].payload.content).toBe("Hello");
    expect(events[1]).toMatchObject({ type: "status" });

    await stream.cancel();
  });
});

async function respondWithJson(res: ServerResponse, fixturePath: string) {
  const fullPath = path.join(fixturesDir, fixturePath);
  const raw = await readFile(fullPath, "utf8");
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(raw);
}

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of req) {
    chunks.push(chunk as Uint8Array);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return {};
  }
}
