import assert from "node:assert/strict";
import test from "node:test";
import { encounterRecordsToSeeds, extractEncounterQuestion } from "../src/learning/assistant-encounter-corpus.js";

test("encounter request extraction keeps only the redacted human question", () => {
  const question = extractEncounterQuestion([
    "Question: Can you check <@U123ABC> and token=secret-value-1234567890?",
    "Answer: This prior assistant prose must not become a training target.",
    "Actions taken: none",
  ].join("\n"));
  assert.equal(question?.includes("prior assistant prose"), false);
  assert.equal(question?.includes("U123ABC"), false);
  assert.equal(question?.includes("secret-value-1234567890"), false);
  assert.match(question ?? "", /\[person\]/);
});

test("encounter request extraction handles DynamoDB-cleaned one-line stories", () => {
  const question = extractEncounterQuestion("Question: What changed in the release? Answer: Prior assistant prose. Delivery: 1/1.");
  assert.equal(question, "What changed in the release?");
});

test("encounter seeds exclude machine handoffs, deduplicate requests, and hash source identity", () => {
  const records = [
    {
      id: "raw-record-one",
      details: "Question: Check the prod release.\nAnswer: old answer",
      outcome: "answered",
      senderKind: "human",
      trafficKind: "human_request",
      createdAt: "2026-07-15T10:00:00Z",
      tags: ["human-request"],
    },
    {
      id: "raw-record-two",
      details: "Question: check the prod release!\nAnswer: another old answer",
      outcome: "answered",
      senderKind: "human",
      trafficKind: "human_request",
      createdAt: "2026-07-15T09:00:00Z",
      tags: ["human-request"],
    },
    {
      id: "machine-record",
      details: "Question: Daily digest\nAnswer: ignored",
      outcome: "answered",
      senderKind: "bot",
      trafficKind: "machine_handoff",
      tags: ["machine-handoff"],
    },
  ];
  const seeds = encounterRecordsToSeeds(records, { limit: 20 });
  assert.equal(seeds.length, 1);
  assert.match(seeds[0]!.id, /^encounter-[a-f0-9]{20}$/);
  assert.equal(seeds[0]!.id.includes("raw-record"), false);
  assert.equal(seeds[0]!.question, "Check the prod release.");
});
