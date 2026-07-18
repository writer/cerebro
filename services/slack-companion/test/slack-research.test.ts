import assert from "node:assert/strict";
import test from "node:test";
import { SlackResearchClient } from "../src/slack/research/index.js";
import { testConfig } from "./fixtures.js";

test("Slack scope capability probe reads granted OAuth scopes", async () => {
  const previousFetch = globalThis.fetch;
  const calls: Array<{ url: string; body: string }> = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(input), body: String(init?.body ?? "") });
    return new Response(JSON.stringify({
      ok: true,
      user_id: "U0BOT",
      team_id: "TWRITER",
      enterprise_id: "EWRITER",
      url: "https://writer.slack.com/",
    }), {
      headers: {
        "x-oauth-scopes": "chat:write,users:read,pins:read,search:read.public",
      },
    });
  }) as typeof fetch;

  try {
    const client = new SlackResearchClient(testConfig());
    const result = await client.scopeCapabilities();

    assert.equal(calls[0]?.url, "https://slack.com/api/auth.test");
    assert.equal(result.ok, true);
    assert.equal(result.bot_user_id, "U0BOT");
    assert.deepEqual(result.granted_scopes, ["chat:write", "pins:read", "search:read.public", "users:read"]);
    assert.equal(result.capabilities.find((capability) => capability.name === "Slack AI search for public content")?.available, true);
    assert.equal(result.capabilities.find((capability) => capability.name === "user profile lookup")?.available, true);
    assert.equal(result.capabilities.find((capability) => capability.name === "file metadata lookup")?.available, false);
    assert.equal(result.missing_recommended_scopes.includes("files:read"), true);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("Slack assistant AI search context parses source-backed results", async () => {
  const previousFetch = globalThis.fetch;
  const calls: Array<{ url: string; body: string }> = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(input), body: String(init?.body ?? "") });
    return new Response(JSON.stringify({
      ok: true,
      response_metadata: { next_cursor: "cursor-2" },
      results: {
        messages: [{
          channel_id: "CSEC",
          channel_name: "security-team-agents",
          message_ts: "1782488940.000000",
          author_user_id: "UUSER",
          author_name: "Jonathan Haas",
          content: "Can someone check whether this alert is noisy?",
          permalink: "https://writer.slack.com/archives/CSEC/p1782488940000000",
          context_messages: {
            before: [{ "user_id:": "UALERT", ts: "1782488900.000000", text: "GitHub identity not linked to Okta" }],
            after: [{ user_id: "UUSER", ts: "1782488960.000000", text: "false positive?" }],
          },
        }],
        files: [{
          file_id: "F123",
          title: "alert.json",
          file_type: "json",
          permalink: "https://writer.slack.com/files/F123",
          content: "raw scanner output",
        }],
        channels: [{ channel_id: "CSEC", name: "security-team-agents", purpose: "Security agent testing" }],
        users: [{ user_id: "UUSER", name: "jonathan.haas", profile: { title: "Security" } }],
      },
    }));
  }) as typeof fetch;

  try {
    const client = new SlackResearchClient(testConfig());
    const result = await client.assistantSearchContext({
      query: "noisy GitHub identity alert",
      limit: 5,
      contentTypes: ["messages", "files"],
      channelTypes: ["public_channel", "private_channel"],
      includeContextMessages: true,
      contextChannelId: "CSEC",
      sort: "timestamp",
      sortDir: "desc",
    });

    assert.equal(calls[0]?.url, "https://slack.com/api/assistant.search.context");
    const body = new URLSearchParams(calls[0]?.body);
    assert.equal(body.get("query"), "noisy GitHub identity alert");
    assert.equal(body.get("content_types"), "messages,files");
    assert.equal(body.get("channel_types"), "public_channel,private_channel");
    assert.equal(body.get("include_context_messages"), "true");
    assert.equal(body.get("context_channel_id"), "CSEC");
    assert.equal(result.ok, true);
    assert.equal(result.next_cursor, "cursor-2");
    assert.equal(result.results?.messages[0]?.ts, "1782488940.000000");
    assert.equal(result.results?.messages[0]?.channel_name, "security-team-agents");
    assert.equal(result.results?.messages[0]?.text, "Can someone check whether this alert is noisy?");
    assert.equal(result.results?.messages[0]?.context_messages?.before[0]?.text, "GitHub identity not linked to Okta");
    assert.equal(result.results?.messages[0]?.context_messages?.before[0]?.user_id, "UALERT");
    assert.equal(result.results?.files[0]?.file_id, "F123");
    assert.equal(result.results?.users[0]?.title, "Security");
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("Slack message search can match two-letter author names", async () => {
  const previousFetch = globalThis.fetch;
  const calls: Array<{ url: string; body: string }> = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(input), body: String(init?.body ?? "") });
    const url = String(input);
    if (url.includes("conversations.info")) {
      return new Response(JSON.stringify({ ok: true, channel: { id: "CSEC", name: "security-team-agents", is_member: true } }));
    }
    if (url.includes("conversations.history")) {
      return new Response(JSON.stringify({
        ok: true,
        messages: [
          { user: "UJR", ts: "1782498781.026289", text: "maybe this entire team..." },
          { user: "UOTHER", ts: "1782498700.000000", text: "unrelated status" },
        ],
      }));
    }
    if (url.includes("users.info")) {
      const body = new URLSearchParams(String(init?.body ?? ""));
      const user = body.get("user");
      return new Response(JSON.stringify({
        ok: true,
        user: user === "UJR"
          ? { name: "jr", profile: { display_name: "jr", real_name: "Seán" } }
          : { name: "other", profile: { display_name: "other" } },
      }));
    }
    return new Response(JSON.stringify({ ok: false, error: "unexpected_method" }));
  }) as typeof fetch;

  try {
    const client = new SlackResearchClient(testConfig());
    const result = await client.searchMessages({
      query: "JR",
      authorQuery: "JR",
      days: 1,
      channelIds: ["CSEC"],
      limit: 5,
      maxChannels: 1,
    });

    assert.equal(result.hits.length, 1);
    assert.equal(result.hits[0]?.user_name, "jr");
    assert.match(result.hits[0]?.text ?? "", /maybe this entire team/);
    assert.equal(calls.some((call) => call.url.includes("users.info")), true);
  } finally {
    globalThis.fetch = previousFetch;
  }
});
