import assert from "node:assert/strict";
import test from "node:test";
import { conversationOperatingStandard } from "../src/agent/conversation-standard.js";

test("conversation standard keeps voice, continuity, and debugging guidance together", () => {
  const assistant = conversationOperatingStandard("assistant").join("\n");
  assert.match(assistant, /stable voice across turns/);
  assert.match(assistant, /remembered preferences, prior sessions, and thread context/);
  assert.match(assistant, /verify mutable current state with live tools/);
  assert.match(assistant, /what is running, what is missing or broken/);
  assert.match(assistant, /do not claim emotions or praise yourself/);
  assert.match(assistant, /exact capability conditions, counts, and partial-coverage boundaries/);
  assert.match(assistant, /resumable work with acceptance criteria/);
  assert.match(assistant, /Do not add a limitation from background self-context/);
  assert.match(assistant, /internal tool names, schemas, routes, and status codes/);
  assert.match(assistant, /greetings, casual check-ins, and open-ended prompts/);
  assert.match(assistant, /Do not replay security findings, identity details, private thread contents/);
  assert.match(assistant, /operating normally and ready/);
  assert.match(assistant, /Offer only directions named by the supplied capability evidence/);
  assert.match(assistant, /findings, runtime health, and release changes/);
  assert.match(assistant, /declarative readiness statement rather than a scope question/);
  assert.match(assistant, /broad question about a source or product such as Okta/);
  assert.match(assistant, /person, account, email address, or finding-specific detail/);
  assert.match(assistant, /never mention an evaluation, fixture, harness, or test context in Slack/);
  assert.match(assistant, /refuse only that action and complete the supported safe path/);
  assert.match(assistant, /whether the prohibited value or action was retrieved or performed/);
  assert.match(assistant, /route the user through any eligible workflow/);
  assert.match(assistant, /Preserve non-sensitive secret names and paths as natural noun phrases/);
  assert.match(assistant, /never format an identifier as 'secret=NAME'/);
  assert.match(assistant, /details the evidence already resolves/);
  assert.match(assistant, /Prefer one compact Slack message/);
  assert.match(assistant, /Resolve scope from the request, thread, durable state/);
  assert.match(assistant, /Do not promise future work/);
  assert.match(assistant, /private continuity state/);
  assert.match(assistant, /completed source results as durable/);
  assert.match(assistant, /identity or namesake collisions/);
  assert.match(assistant, /same subject, property, and relevant time/);
  assert.match(assistant, /Do not append blanket uncertainty/);
  assert.match(assistant, /Similar names do not establish identity, ownership/);
  assert.match(assistant, /Map every claim to exactly one correct identity/);
  assert.match(assistant, /verify each attribution against its own source/);
  assert.match(assistant, /name the document, PR, or record you will correct/);
  assert.match(assistant, /already authorizes pursuing an action/);
  assert.match(assistant, /avoid comparative spin/);
  assert.match(assistant, /which sources genuinely failed/);
});

test("repair standard preserves completed evidence and material facts in Slack-facing messages", () => {
  const repair = conversationOperatingStandard("repair").join("\n");
  assert.match(repair, /rewrite Slack-facing messages into natural thread replies/);
  assert.match(repair, /Put detailed checks in structured fields/);
  assert.match(repair, /never replace completed evidence with an internal failure notice/);
  assert.match(repair, /Structured evidence, next-action, and teammate fields cannot substitute/);
  assert.match(repair, /Distinct identities, stale history, partial coverage/);
  assert.match(repair, /exact unresolved source state/);
});

test("triage standard keeps low-value alert chatter quiet", () => {
  const triage = conversationOperatingStandard("triage").join("\n");
  assert.match(triage, /stay quiet unless speaking changes a check/);
  assert.match(triage, /one useful Slack reply from a teammate/);
});
