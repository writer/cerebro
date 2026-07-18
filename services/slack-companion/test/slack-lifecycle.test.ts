import assert from "node:assert/strict";
import test from "node:test";
import {
  lifecycleText,
  postLifecycleNotice,
  releaseStartedText,
  releaseTerminalText,
  startReleaseNoticeMonitor,
} from "../src/slack/lifecycle.js";
import type { ReleaseReceipt } from "../src/slack/release-receipt.js";
import { testConfig } from "./fixtures.js";

test("unrecorded shutdown copy names the availability risk and active commit", () => {
  const text = lifecycleText(testConfig({ coordination: {
    version: "sha-test",
    commitSubject: "Add runtime evidence to restart notices",
  } }), { phase: "stopping", signal: "SIGTERM" }, {
    desiredCount: 1,
    runningCount: 1,
    pendingCount: 0,
  });

  assert.match(text, /stopping outside a recorded deployment/);
  assert.match(text, /Slack replies may pause/);
  assert.match(text, /Current commit sha-test: Add runtime evidence to restart notices/);
});

test("release start copy reports concrete work and pending checks without asserting health", () => {
  const text = releaseStartedText(releaseReceipt({
    commitSubject: "Join <deploy> & runtime evidence (#153)",
    components: ["Slack runtime", "deployment infrastructure"],
    changedFileCount: 9,
  }));

  assert.match(text, /Deployment started for commit sha-1234567/);
  assert.match(text, /Join &lt;deploy&gt; &amp; runtime evidence/);
  assert.match(text, /Mode: ECS application update/);
  assert.match(text, /Components: Slack runtime, deployment infrastructure/);
  assert.match(text, /Checks running: Slack release message, ECS image, runtime configuration, and Cerebro API/);
  assert.match(text, /<https:\/\/github\.com\/WriterInternal\/cerebro-slack-companion\/actions\/runs\/123\|Deploy run>/);
  assert.doesNotMatch(text, /healthy|back online/i);
});

test("verified release copy requires all named checks and reports worker state", () => {
  const text = releaseTerminalText(releaseReceipt({
    status: "verified",
    runningVersion: "sha-1234567",
    checks: passedChecks(),
  }), {
    desiredCount: 2,
    runningCount: 2,
    pendingCount: 0,
  });

  assert.match(text, /Deployment verified\. Running version sha-1234567/);
  assert.match(text, /Workers running: 2\/2/);
  assert.match(text, /Checks passed: Slack release message, ECS image, runtime configuration, and Cerebro API/);
});

test("rolled back release copy reports the restored version and failed checks", () => {
  const text = releaseTerminalText(releaseReceipt({
    status: "rolled_back",
    runningVersion: "sha-previous",
    previousVersion: "sha-previous",
    failedChecks: ["runtime configuration", "Cerebro API"],
    statusDetail: "ECS deployment circuit breaker restored the previous task definition.",
  }));

  assert.match(text, /Deployment rolled back\. Restored version sha-previous/);
  assert.match(text, /Failed checks: runtime configuration, Cerebro API/);
});

test("recorded deployment creates one release parent and records the Slack check", async () => {
  const messages: any[] = [];
  const completed: any[] = [];
  const checks: any[] = [];
  const receipt = releaseReceipt();
  const coordinator = lifecycleCoordinator({
    activeReleaseReceipt: async () => receipt,
    claimReleaseNotice: async () => ({ claimed: true, reason: "claimed" }),
    completeReleaseNotice: async (input: any) => completed.push(input),
    markReleaseSlackCheck: async (...input: any[]) => checks.push(input),
  });
  const config = testConfig({
    slack: { lifecycleChannelIds: new Set(["CSEC", "COPS"]) },
    coordination: { version: receipt.version },
  });

  await postLifecycleNotice(config, coordinator, slackClient(messages), { phase: "started" });

  assert.equal(messages.length, 2);
  assert.deepEqual(messages.map((message) => message.channel), ["CSEC", "COPS"]);
  assert.ok(messages.every((message) => !message.thread_ts));
  assert.equal(completed.length, 2);
  assert.deepEqual(checks, [[receipt.version, "passed", "Release thread created in 2/2 configured channel(s)."]]);
});

test("routine HA worker scaling produces no lifecycle message when availability is unchanged", async () => {
  const messages: any[] = [];
  const coordinator = lifecycleCoordinator({
    serviceSnapshot: async () => ({ desiredCount: 3, runningCount: 3, pendingCount: 0 }),
  });

  await postLifecycleNotice(testConfig(), coordinator, slackClient(messages), { phase: "started" });

  assert.equal(messages.length, 0);
});

test("unrecorded restart reports restart-loop count and ECS stop evidence", async () => {
  const messages: any[] = [];
  const coordinator = lifecycleCoordinator({
    recordStartup: async () => ({ count: 3, durable: true, loopDetected: true, windowMinutes: 15, startedAt: "2026-07-15T12:00:00.000Z" }),
    recentStoppedTask: async () => ({
      stopCode: "EssentialContainerExited",
      stoppedReason: "Essential container in task exited",
      exitCode: 137,
    }),
  });

  await postLifecycleNotice(testConfig({ coordination: {
    version: "sha-current",
    commitSubject: "Record release verification",
  } }), coordinator, slackClient(messages), { phase: "started" });

  assert.equal(messages.length, 1);
  assert.match(messages[0].text, /restarted outside a recorded deployment/);
  assert.match(messages[0].text, /Restart loop detected: 3 starts in 15 minutes/);
  assert.match(messages[0].text, /EssentialContainerExited — exit code 137 — Essential container in task exited/);
  assert.match(messages[0].text, /Deployment health has not been asserted/);
});

test("terminal release state is posted in the existing release thread", async () => {
  const messages: any[] = [];
  const receipt = releaseReceipt({
    status: "failed",
    runningVersion: "sha-previous",
    failedChecks: ["Cerebro API"],
    threadTsByChannel: { CSEC: "1700.1" },
  });
  const coordinator = lifecycleCoordinator({
    activeReleaseReceipt: async () => receipt,
    claimReleaseNotice: async () => ({ claimed: true, reason: "claimed" }),
  });

  const monitor = startReleaseNoticeMonitor(
    testConfig({ coordination: { version: receipt.version } }),
    coordinator,
    slackClient(messages),
  );
  await new Promise((resolve) => setTimeout(resolve, 20));
  monitor.stop();

  assert.equal(messages.length, 1);
  assert.equal(messages[0].thread_ts, "1700.1");
  assert.match(messages[0].text, /Deployment failed verification/);
});

test("an old terminal receipt does not hide a later unrecorded restart", async () => {
  const messages: any[] = [];
  const receipt = releaseReceipt({ status: "verified", checks: passedChecks() });
  const coordinator = lifecycleCoordinator({
    activeReleaseReceipt: async () => receipt,
    recordStartup: async () => ({
      count: 2,
      durable: true,
      loopDetected: false,
      windowMinutes: 15,
      startedAt: "2026-07-15T13:00:00.000Z",
    }),
    recentStoppedTask: async () => ({ stopCode: "TaskFailedToStart", stoppedReason: "Resource initialization error" }),
  });

  await postLifecycleNotice(
    testConfig({ coordination: { version: receipt.version } }),
    coordinator,
    slackClient(messages),
    { phase: "started" },
  );

  assert.equal(messages.length, 1);
  assert.match(messages[0].text, /restarted outside a recorded deployment/);
  assert.match(messages[0].text, /TaskFailedToStart/);
});

function lifecycleCoordinator(overrides: Record<string, unknown> = {}): any {
  return {
    activeReleaseReceipt: async () => undefined,
    serviceSnapshot: async () => ({ desiredCount: 1, runningCount: 1, pendingCount: 0 }),
    recordStartup: async () => ({ count: 1, durable: true, loopDetected: false, windowMinutes: 15, startedAt: "2026-07-15T12:00:00.000Z" }),
    recentStoppedTask: async () => undefined,
    claimLifecycleNotice: async () => ({ claimed: true, reason: "claimed" }),
    claimReleaseNotice: async () => ({ claimed: false, reason: "already_sent" }),
    completeReleaseNotice: async () => undefined,
    markReleaseSlackCheck: async () => undefined,
    ...overrides,
  };
}

function slackClient(messages: any[]): any {
  return {
    chat: {
      postMessage: async (message: any) => {
        messages.push(message);
        return { ts: `${1700 + messages.length}.1` };
      },
    },
  };
}

function passedChecks(): ReleaseReceipt["checks"] {
  return {
    slack: { status: "passed" },
    image: { status: "passed" },
    runtime: { status: "passed" },
    cerebro: { status: "passed" },
  };
}

function releaseReceipt(overrides: Partial<ReleaseReceipt> = {}): ReleaseReceipt {
  return {
    schemaVersion: 1,
    recordType: "companion_release_receipt",
    version: "sha-1234567",
    previousVersion: "sha-previous",
    commitSha: "1234567890abcdef",
    commitSubject: "Join deploy and runtime evidence (#153)",
    deployMode: "ecs",
    deployReason: "container_input_changed",
    components: ["Slack runtime"],
    changedFileCount: 4,
    status: "deploying",
    statusDetail: "Deployment checks are running.",
    failedChecks: [],
    checks: {
      slack: { status: "pending" },
      image: { status: "pending" },
      runtime: { status: "pending" },
      cerebro: { status: "pending" },
    },
    commitUrl: "https://github.com/WriterInternal/cerebro-slack-companion/commit/1234567890abcdef",
    pullRequestUrl: "https://github.com/WriterInternal/cerebro-slack-companion/pull/153",
    deployRunUrl: "https://github.com/WriterInternal/cerebro-slack-companion/actions/runs/123",
    startedAt: "2026-07-15T12:00:00.000Z",
    updatedAt: "2026-07-15T12:00:00.000Z",
    threadTsByChannel: {},
    notificationClaims: {},
    notifications: {},
    ...overrides,
  };
}
