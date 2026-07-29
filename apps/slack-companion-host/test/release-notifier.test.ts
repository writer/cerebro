import assert from "node:assert/strict";
import test from "node:test";
import {
  postReleaseState,
  type ReleaseNoticeSlackClient,
  type ReleaseNoticeStore,
  type ReleaseReceipt,
  releaseStartedText,
  releaseTerminalText,
} from "../src/runtime/release-notifier.js";

class MemoryReleaseStore implements ReleaseNoticeStore {
  readonly claims: Array<{ channelId: string; state: string; version: string }> = [];
  readonly completions: Array<{
    channelId: string;
    state: string;
    threadTs?: string;
    version: string;
  }> = [];
  readonly passed: Array<{ detail: string; version: string }> = [];
  claimResult = true;

  async activeReceipt(): Promise<ReleaseReceipt | undefined> {
    return undefined;
  }

  async claim(input: {
    channelId: string;
    leaseSeconds: number;
    state: string;
    version: string;
  }): Promise<boolean> {
    this.claims.push(input);
    return this.claimResult;
  }

  async complete(input: {
    channelId: string;
    state: string;
    threadTs?: string;
    version: string;
  }): Promise<void> {
    this.completions.push(input);
  }

  async markSlackPassed(version: string, detail: string): Promise<void> {
    this.passed.push({ detail, version });
  }
}

function receipt(
  overrides: Partial<ReleaseReceipt> = {},
): ReleaseReceipt {
  return {
    changedFileCount: 2,
    checks: { slack: { status: "pending" } },
    commitSubject: "Repair <runtime> & lifecycle.",
    commitUrl: "https://github.com/writer/cerebro/commit/abc",
    components: ["Slack runtime"],
    deployMode: "ecs",
    deployRunUrl: "https://github.com/WriterInternal/cerebro/actions/runs/1",
    failedChecks: [],
    notificationClaims: {},
    notifications: {},
    status: "deploying",
    statusDetail: "Deployment checks are running.",
    threadTsByChannel: {},
    version: "sha-abc",
    ...overrides,
  };
}

function slackClient(): {
  client: ReleaseNoticeSlackClient;
  messages: Array<{
    channel: string;
    text: string;
    thread_ts?: string;
  }>;
} {
  const messages: Array<{
    channel: string;
    text: string;
    thread_ts?: string;
  }> = [];
  return {
    client: {
      chat: {
        async postMessage(input) {
          messages.push(input);
          return { ts: "1785000000.000001" };
        },
      },
    },
    messages,
  };
}

test("deploying release creates one claimed thread and passes the Slack check", async () => {
  const store = new MemoryReleaseStore();
  const slack = slackClient();
  await postReleaseState(store, slack.client, receipt(), ["C-ONE"]);

  assert.deepEqual(store.claims.map(({ channelId, state }) => ({
    channelId,
    state,
  })), [{ channelId: "C-ONE", state: "started" }]);
  assert.equal(slack.messages.length, 1);
  assert.equal(slack.messages[0]?.thread_ts, undefined);
  assert.deepEqual(store.completions, [{
    channelId: "C-ONE",
    state: "started",
    threadTs: "1785000000.000001",
    version: "sha-abc",
  }]);
  assert.deepEqual(store.passed, [{
    detail: "Release thread created in 1/1 configured channel(s).",
    version: "sha-abc",
  }]);
});

test("an existing release thread receives one terminal reply", async () => {
  const store = new MemoryReleaseStore();
  const slack = slackClient();
  await postReleaseState(store, slack.client, receipt({
    checks: { slack: { status: "passed" } },
    runningVersion: "sha-abc",
    status: "verified",
    statusDetail: "All checks passed.",
    threadTsByChannel: { "C-ONE": "1785000000.000001" },
  }), ["C-ONE"]);

  assert.deepEqual(store.claims.map(({ state }) => state), ["verified"]);
  assert.equal(slack.messages[0]?.thread_ts, "1785000000.000001");
  assert.match(slack.messages[0]?.text ?? "", /Deployment verified/u);
  assert.deepEqual(store.completions[0], {
    channelId: "C-ONE",
    state: "verified",
    version: "sha-abc",
  });
  assert.deepEqual(store.passed, []);
});

test("a competing worker lease prevents duplicate Slack messages", async () => {
  const store = new MemoryReleaseStore();
  store.claimResult = false;
  const slack = slackClient();
  await postReleaseState(store, slack.client, receipt(), ["C-ONE"]);

  assert.equal(slack.messages.length, 0);
  assert.deepEqual(store.completions, []);
  assert.deepEqual(store.passed, []);
});

test("an unconfirmed Slack post is observable and cannot pass the release check", async () => {
  const store = new MemoryReleaseStore();
  const errors: unknown[] = [];
  const client: ReleaseNoticeSlackClient = {
    chat: {
      async postMessage() {
        return {};
      },
    },
  };
  await postReleaseState(
    store,
    client,
    receipt(),
    ["C-ONE"],
    (error) => errors.push(error),
  );

  assert.equal(errors.length, 1);
  assert.deepEqual(store.completions, []);
  assert.deepEqual(store.passed, []);
});

test("release copy escapes Slack control text and rejects non-GitHub links", () => {
  const unsafe = receipt({
    commitSubject: "Ship <@U123> & verify",
    commitUrl: "https://attacker.example/commit/abc",
  });
  const started = releaseStartedText(unsafe);
  const terminal = releaseTerminalText({
    ...unsafe,
    failedChecks: ["runtime <check>"],
    runningVersion: "sha-failed",
    status: "failed",
    statusDetail: "A <failure> & retry.",
  });

  assert.doesNotMatch(started, /attacker/u);
  assert.match(started, /&lt;@U123&gt; &amp; verify/u);
  assert.match(terminal, /runtime &lt;check&gt;/u);
  assert.match(terminal, /A &lt;failure&gt; &amp; retry/u);
});
