import assert from "node:assert/strict";
import test from "node:test";

import { latestAssistantText } from "../src/triage/alert-triage-transcript.js";

test("returns text parts from the latest assistant message in source order", () => {
  assert.equal(
    latestAssistantText([
      { role: "assistant", content: [{ type: "text", text: "stale answer" }] },
      { role: "user", content: [{ type: "text", text: "follow-up" }] },
      {
        role: "assistant",
        content: [
          { type: "text", text: "  current conclusion" },
          { type: "toolCall", name: "lookup" },
          { type: "text", text: "next action  " },
        ],
      },
      { role: "tool", content: [{ type: "text", text: "tool output" }] },
    ]),
    "current conclusion\nnext action",
  );
});

test("skips assistant records whose content is not an array", () => {
  assert.equal(
    latestAssistantText([
      { role: "assistant", content: [{ type: "text", text: "usable answer" }] },
      { role: "assistant", content: "not structured content" },
    ]),
    "usable answer",
  );
});

test("does not reuse stale text when the latest assistant message has no text", () => {
  assert.equal(
    latestAssistantText([
      { role: "assistant", content: [{ type: "text", text: "stale answer" }] },
      {
        role: "assistant",
        content: [null, "invalid", { type: "toolCall", name: "lookup" }, { type: "text", text: 42 }],
      },
    ]),
    "",
  );
});

test("returns empty text when no structured assistant message exists", () => {
  assert.equal(latestAssistantText([null, 42, { role: "user", content: [] }]), "");
});
