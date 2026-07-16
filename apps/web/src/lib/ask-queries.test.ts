import { describe, expect, it } from "vitest";

import {
  type AskQuery,
  askQueryCreatePayload,
  defaultAskQueryName,
  sortAskQueries,
  summarizeQuestion,
  validateAskQueryName,
} from "@/lib/ask-queries";

const makeQuery = (overrides: Partial<AskQuery>): AskQuery => ({
  id: "ask-query-1",
  tenant_id: "local",
  name: "q",
  question: "question?",
  pinned: false,
  created_at: "2026-06-22T00:00:00Z",
  updated_at: "2026-06-22T00:00:00Z",
  ...overrides,
});

describe("defaultAskQueryName", () => {
  it("collapses whitespace and keeps short questions intact", () => {
    expect(defaultAskQueryName("  Which   admins\nare stale? ")).toBe("Which admins are stale?");
  });

  it("truncates long questions with an ellipsis", () => {
    const long = "a".repeat(80);
    const name = defaultAskQueryName(long);
    expect(name.endsWith("…")).toBe(true);
    expect(name.length).toBeLessThanOrEqual(58);
  });
});

describe("validateAskQueryName", () => {
  it("rejects an empty name", () => {
    expect(validateAskQueryName("   ")).toEqual({ ok: false, error: "Name is required." });
  });

  it("trims and accepts a valid name", () => {
    expect(validateAskQueryName("  Stale admins  ")).toEqual({ ok: true, name: "Stale admins" });
  });

  it("rejects an over-long name", () => {
    const result = validateAskQueryName("x".repeat(201));
    expect(result.ok).toBe(false);
  });
});

describe("sortAskQueries", () => {
  it("orders pinned first then newest, without mutating input", () => {
    const input = [
      makeQuery({ id: "a", pinned: false, created_at: "2026-06-20T00:00:00Z" }),
      makeQuery({ id: "b", pinned: true, created_at: "2026-06-19T00:00:00Z" }),
      makeQuery({ id: "c", pinned: false, created_at: "2026-06-21T00:00:00Z" }),
    ];
    const sorted = sortAskQueries(input);
    expect(sorted.map((query) => query.id)).toEqual(["b", "c", "a"]);
    expect(input.map((query) => query.id)).toEqual(["a", "b", "c"]);
  });
});

describe("summarizeQuestion", () => {
  it("truncates long questions", () => {
    expect(summarizeQuestion("a".repeat(200), 10)).toBe(`${"a".repeat(9)}…`);
  });

  it("keeps short questions", () => {
    expect(summarizeQuestion("short")).toBe("short");
  });
});

describe("askQueryCreatePayload", () => {
  it("omits empty optional fields and trims values", () => {
    expect(
      askQueryCreatePayload({ name: " name ", question: " q? ", scopeUrn: "  ", model: "" }),
    ).toEqual({ name: "name", question: "q?" });
  });

  it("includes scope, model, and pinned when present", () => {
    expect(
      askQueryCreatePayload({
        name: "n",
        question: "q",
        scopeUrn: "urn:cerebro:local:identity:admin",
        model: "claude-sonnet-4-6",
        pinned: true,
      }),
    ).toEqual({
      name: "n",
      question: "q",
      scope_urn: "urn:cerebro:local:identity:admin",
      model: "claude-sonnet-4-6",
      pinned: true,
    });
  });
});
