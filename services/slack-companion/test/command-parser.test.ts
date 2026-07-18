import assert from "node:assert/strict";
import test from "node:test";
import { commandHelpEntries, parseCommand, validateCommandRegistry, type CommandDefinition } from "../src/slack/command-parser.js";

test("parseCommand returns help for empty input", () => {
  assert.deepEqual(parseCommand(""), { name: "help" });
});

test("parseCommand parses evidence arguments", () => {
  assert.deepEqual(parseCommand("evidence writer-okta finding-1"), {
    name: "evidence",
    runtimeId: "writer-okta",
    findingId: "finding-1",
  });
});

test("parseCommand parses command aliases through the registry", () => {
  assert.deepEqual(parseCommand("finding writer-okta"), {
    name: "findings",
    runtimeId: "writer-okta",
  });
  assert.deepEqual(parseCommand("runbooks"), { name: "skills" });
  assert.deepEqual(parseCommand("runbook login-posture focus on Okta"), {
    name: "skill",
    skillId: "login-posture",
    details: "focus on Okta",
  });
  assert.deepEqual(parseCommand("jobs"), { name: "schedules" });
  assert.deepEqual(parseCommand("cron run sched-123"), {
    name: "schedule_run",
    jobId: "sched-123",
  });
});

test("parseCommand treats unknown command as ask text", () => {
  assert.deepEqual(parseCommand("why is this open?"), {
    name: "ask",
    question: "why is this open?",
  });
});

test("parseCommand rejects missing runtime for source writes", () => {
  assert.throws(() => parseCommand("sync"), /runtime-id/);
});

test("parseCommand parses skill commands", () => {
  assert.deepEqual(parseCommand("skill login-posture focus on Okta"), {
    name: "skill",
    skillId: "login-posture",
    details: "focus on Okta",
  });
});

test("parseCommand parses plain-language schedule creation", () => {
  assert.deepEqual(parseCommand("schedule every weekday at 9am run login posture  then scary findings"), {
    name: "schedule_create",
    text: "every weekday at 9am run login posture  then scary findings",
  });
});

test("parseCommand parses schedule controls", () => {
  assert.deepEqual(parseCommand("schedule run sched-123"), {
    name: "schedule_run",
    jobId: "sched-123",
  });
  assert.deepEqual(parseCommand("schedules"), { name: "schedules" });
});

test("parseCommand parses autonomy goal commands", () => {
  assert.deepEqual(parseCommand("goal fix the flaky Cerebro CI check"), {
    name: "goal_create",
    text: "fix the flaky Cerebro CI check",
  });
  assert.deepEqual(parseCommand("goals active"), {
    name: "goals",
    status: "active",
  });
  assert.deepEqual(parseCommand("goal show goal-123"), {
    name: "goal_show",
    goalId: "goal-123",
  });
  assert.deepEqual(parseCommand("goal pause goal-123"), {
    name: "goal_pause",
    goalId: "goal-123",
  });
  assert.deepEqual(parseCommand("goal resume goal-123"), {
    name: "goal_resume",
    goalId: "goal-123",
  });
  assert.deepEqual(parseCommand("goal cancel goal-123"), {
    name: "goal_cancel",
    goalId: "goal-123",
  });
  assert.deepEqual(parseCommand("goal done goal-123 merged PR 17"), {
    name: "goal_complete",
    goalId: "goal-123",
    summary: "merged PR 17",
  });
});

test("parseCommand parses operator commands", () => {
  assert.deepEqual(parseCommand("operator"), {
    name: "operator",
    action: "whoami",
  });
  assert.deepEqual(parseCommand("operator deploy"), {
    name: "operator",
    action: "deploy",
  });
  assert.deepEqual(parseCommand("ops autodeploy"), {
    name: "operator",
    action: "deploy",
  });
  assert.deepEqual(parseCommand("operator health"), {
    name: "operator",
    action: "health",
  });
  assert.throws(() => parseCommand("operator purge"), /operator whoami/);
});

test("parseCommand rejects unknown goal status", () => {
  assert.throws(() => parseCommand("goals noisy"), /Goal status/);
});

test("commandHelpEntries exposes concrete usage copy from the registry", () => {
  const entries = commandHelpEntries();

  assert.ok(entries.length >= 10);
  assert.ok(entries.every((entry) => entry.usage.startsWith("/cerebro ")));
  assert.ok(entries.some((entry) => entry.command === "schedule" && entry.aliases.includes("cron")));
  assert.ok(entries.some((entry) => entry.command === "goal" && entry.usage === "/cerebro goal <objective>"));
  assert.ok(entries.some((entry) => entry.command === "skill" && entry.summary.includes("Run")));
});

test("validateCommandRegistry rejects duplicate command names and aliases", () => {
  const parse = () => ({ name: "help" as const });
  const registry: CommandDefinition[] = [
    { command: "one", usage: "/cerebro one", summary: "One.", parse },
    { command: "two", aliases: ["one"], usage: "/cerebro two", summary: "Two.", parse },
  ];

  assert.throws(() => validateCommandRegistry(registry), /registered by both one and two/);
});
