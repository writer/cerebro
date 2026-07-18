import assert from "node:assert/strict";
import test from "node:test";
import { answerFromGraphReason } from "../src/slack/format.js";

test("answerFromGraphReason does not invent linked evidence", () => {
  const answer = answerFromGraphReason({
    events: [{ type: "graph_context_returned" }],
  });

  assert.doesNotMatch(answer, /linked evidence/i);
  assert.match(answer, /did not return a written graph answer or evidence link/i);
});

test("answerFromGraphReason accepts graph answer_markdown", () => {
  assert.equal(
    answerFromGraphReason({ answer_markdown: "User risk is elevated by one open identity finding." }),
    "User risk is elevated by one open identity finding.",
  );
});

test("answerFromGraphReason includes real evidence links", () => {
  const answer = answerFromGraphReason({
    citations: [{ title: "Identity finding", url: "https://cerebro.example/findings/f-1" }],
  });

  assert.match(answer, /returned graph evidence, but no written answer/i);
  assert.match(answer, /<https:\/\/cerebro\.example\/findings\/f-1\|Identity finding>/);
});

test("answerFromGraphReason appends real evidence to a written answer", () => {
  const answer = answerFromGraphReason({
    answer: "Jonathan's user has one connected high-risk finding.",
    evidence_url: "https://cerebro.example/evidence/e-1",
  });

  assert.match(answer, /^Jonathan's user has one connected high-risk finding\./);
  assert.match(answer, /Evidence: <https:\/\/cerebro\.example\/evidence\/e-1\|Open evidence>/);
});

test("answerFromGraphReason does not treat echoed prompt URLs as evidence", () => {
  const answer = answerFromGraphReason({
    question: "Can you check https://slack.example/archives/CSEC/p123?",
    answer: "I checked the thread URL you sent.",
  });

  assert.equal(answer, "I checked the thread URL you sent.");
});
