import assert from "node:assert/strict";
import test from "node:test";
import { SlackEventCoordinator } from "../src/slack/coordination.js";
import { testConfig } from "./fixtures.js";

const taskDefinitionOne = "arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-slack-companion-sec-dev:1";
const taskDefinitionTwo = "arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-slack-companion-sec-dev:2";

test("slack event coordinator suppresses local duplicate events", async () => {
  const coordinator = new SlackEventCoordinator(testConfig({
    learning: { tableName: undefined },
    coordination: { eventDedupeEnabled: false },
  }));

  const first = await coordinator.claimSlackEvent({ kind: "app_mention", channelId: "CSEC", ts: "1.1" });
  const second = await coordinator.claimSlackEvent({ kind: "app_mention", channelId: "CSEC", ts: "1.1" });

  assert.equal(first.claimed, true);
  assert.equal(first.reason, "claimed_local");
  assert.equal(second.claimed, false);
  assert.equal(second.reason, "local_duplicate");
});

test("slack event coordinator uses DynamoDB conditional claims across workers", async () => {
  const dynamo = new FakeDynamo();
  const config = testConfig({
    learning: { tableName: "learning" },
    coordination: { eventDedupeEnabled: true },
  });
  const firstWorker = new SlackEventCoordinator(config, { dynamo });
  const secondWorker = new SlackEventCoordinator(config, { dynamo });

  const first = await firstWorker.claimSlackEvent({ kind: "message", channelId: "CSEC", ts: "2.2" });
  const second = await secondWorker.claimSlackEvent({ kind: "message", channelId: "CSEC", ts: "2.2" });

  assert.equal(first.claimed, true);
  assert.equal(first.reason, "claimed");
  assert.equal(second.claimed, false);
  assert.equal(second.reason, "durable_duplicate");
});

test("slack event coordinator dedupes lifecycle notices by phase and version", async () => {
  const dynamo = new FakeDynamo();
  const config = testConfig({
    learning: { tableName: "learning" },
    coordination: { eventDedupeEnabled: true, version: "sha-test" },
  });
  const firstWorker = new SlackEventCoordinator(config, { dynamo });
  const secondWorker = new SlackEventCoordinator(config, { dynamo });

  const first = await firstWorker.claimLifecycleNotice({ phase: "started" });
  const second = await secondWorker.claimLifecycleNotice({ phase: "started" });

  assert.equal(first.claimed, true);
  assert.equal(first.reason, "claimed");
  assert.equal(second.claimed, false);
  assert.equal(second.reason, "durable_duplicate");
});

test("slack event coordinator requires allowlisted bot handoffs and applies cooldown", () => {
  let nowMs = Date.parse("2026-07-02T00:00:00Z");
  const coordinator = new SlackEventCoordinator(testConfig({
    slack: {
      assistantBotUserIds: new Set(["BHELPER", "UHELPER"]),
      assistantBotCooldownSeconds: 60,
    },
  }), {
    now: () => new Date(nowMs),
  });

  const human = coordinator.claimBotHandoff({ channelId: "CSEC", ts: "1.1", userId: "UUSER" });
  const denied = coordinator.claimBotHandoff({ channelId: "CSEC", ts: "1.2", botId: "BOTHER", subtype: "bot_message" });
  const first = coordinator.claimBotHandoff({ channelId: "CSEC", threadTs: "1.0", ts: "1.3", botId: "BHELPER", subtype: "bot_message" });
  const second = coordinator.claimBotHandoff({ channelId: "CSEC", threadTs: "1.0", ts: "1.4", botId: "BHELPER", subtype: "bot_message" });
  nowMs += 61_000;
  const third = coordinator.claimBotHandoff({ channelId: "CSEC", threadTs: "1.0", ts: "1.5", botId: "BHELPER", subtype: "bot_message" });
  const userIdAllowed = coordinator.claimBotHandoff({ channelId: "CSEC", threadTs: "2.0", ts: "2.1", botId: "BOTHER", userId: "UHELPER", subtype: "bot_message" });

  assert.equal(human.accepted, true);
  assert.equal(human.reason, "not_bot");
  assert.equal(denied.accepted, false);
  assert.equal(denied.reason, "bot_not_allowed");
  assert.equal(first.accepted, true);
  assert.equal(first.reason, "allowed");
  assert.equal(second.accepted, false);
  assert.equal(second.reason, "cooldown");
  assert.equal(third.accepted, true);
  assert.equal(userIdAllowed.accepted, true);
});

test("slack event coordinator applies channel bot policy and loop limit", () => {
  let nowMs = Date.parse("2026-07-02T00:00:00Z");
  const coordinator = new SlackEventCoordinator(testConfig({
    slack: {
      assistantBotUserIds: new Set(["BGLOBAL"]),
      assistantBotCooldownSeconds: 0,
      assistantBotMaxHandoffsPerThread: 5,
      assistantBotHandoffWindowSeconds: 3_600,
      assistantBotHandoffPolicies: [{
        channelId: "CSEC",
        botUserIds: new Set(["BHELPER"]),
        cooldownSeconds: 0,
        maxHandoffsPerThread: 1,
        windowSeconds: 120,
      }],
    },
  }), {
    now: () => new Date(nowMs),
  });

  const first = coordinator.claimBotHandoff({ channelId: "CSEC", threadTs: "1.0", ts: "1.1", botId: "BHELPER", subtype: "bot_message" });
  const second = coordinator.claimBotHandoff({ channelId: "CSEC", threadTs: "1.0", ts: "1.2", botId: "BHELPER", subtype: "bot_message" });
  const global = coordinator.claimBotHandoff({ channelId: "COTHER", threadTs: "1.0", ts: "1.3", botId: "BGLOBAL", subtype: "bot_message" });
  nowMs += 121_000;
  const afterWindow = coordinator.claimBotHandoff({ channelId: "CSEC", threadTs: "1.0", ts: "1.4", botId: "BHELPER", subtype: "bot_message" });

  assert.equal(first.accepted, true);
  assert.equal(first.policyScope, "channel");
  assert.equal(first.handoffCount, 1);
  assert.equal(second.accepted, false);
  assert.equal(second.reason, "loop_limit");
  assert.equal(second.maxHandoffsPerThread, 1);
  assert.equal(global.accepted, true);
  assert.equal(global.policyScope, "global");
  assert.equal(afterWindow.accepted, true);
});

test("deployment fence lets old task work until replacement is running", async () => {
  const coordinator = new SlackEventCoordinator(testConfig({
    coordination: {
      deploymentFenceEnabled: true,
      ecsClusterName: "cluster",
      ecsServiceName: "service",
    },
  }), {
    ecs: new FakeEcs(taskDefinitionTwo, 0),
    taskIdentityProvider: async () => ({ taskDefinitionArn: taskDefinitionOne }),
  });

  const claim = await coordinator.claimSlackEvent({ kind: "message", channelId: "CSEC", ts: "3.3" });

  assert.equal(claim.claimed, true);
  assert.equal((await coordinator.isCurrentTask()).reason, "replacement_not_running");
});

test("deployment fence suppresses stale task after replacement is running", async () => {
  const coordinator = new SlackEventCoordinator(testConfig({
    coordination: {
      deploymentFenceEnabled: true,
      ecsClusterName: "cluster",
      ecsServiceName: "service",
    },
  }), {
    ecs: new FakeEcs(taskDefinitionTwo, 1),
    taskIdentityProvider: async () => ({ taskDefinitionArn: taskDefinitionOne }),
  });

  const claim = await coordinator.claimSlackEvent({ kind: "message", channelId: "CSEC", ts: "4.4" });

  assert.equal(claim.claimed, false);
  assert.equal(claim.reason, "stale_deployment");
  assert.equal((await coordinator.isCurrentTask()).reason, "stale_deployment");
});

test("release coordination follows the active pointer and validates the receipt", async () => {
  const dynamo = new ReleaseDynamo(releaseItem());
  const coordinator = new SlackEventCoordinator(testConfig({
    learning: { tableName: "learning" },
    coordination: { version: "sha-1234567" },
  }), { dynamo });

  const receipt = await coordinator.activeReleaseReceipt();

  assert.equal(receipt?.version, "sha-1234567");
  assert.equal(receipt?.status, "deploying");
  assert.deepEqual(dynamo.getKeys, ["current", "release#sha-1234567"]);
});

test("release coordination leases and completes one threaded state", async () => {
  const dynamo = new ReleaseDynamo(releaseItem());
  const coordinator = new SlackEventCoordinator(testConfig({
    learning: { tableName: "learning" },
  }), { dynamo, now: () => new Date("2026-07-15T12:00:00.000Z") });

  const claim = await coordinator.claimReleaseNotice({ version: "sha-1234567", channelId: "CSEC", state: "started" });
  await coordinator.completeReleaseNotice({ version: "sha-1234567", channelId: "CSEC", state: "started", threadTs: "1700.1" });
  await coordinator.markReleaseSlackCheck("sha-1234567", "passed", "Release thread created.");

  assert.equal(claim.claimed, true);
  assert.equal(dynamo.updates[0].ExpressionAttributeNames["#claims"], "notificationClaims");
  assert.equal(dynamo.updates[1].ExpressionAttributeNames["#threads"], "threadTsByChannel");
  assert.deepEqual(dynamo.updates[2].ExpressionAttributeValues[":check"], {
    status: "passed",
    detail: "Release thread created.",
  });
});

test("startup coordination detects three starts of the same version in fifteen minutes", async () => {
  const dynamo = new ReleaseDynamo(releaseItem(), [
    { version: "sha-1234567" },
    { version: "sha-1234567" },
    { version: "sha-1234567" },
    { version: "sha-other" },
  ]);
  const coordinator = new SlackEventCoordinator(testConfig({
    learning: { tableName: "learning" },
    coordination: { version: "sha-1234567" },
  }), {
    dynamo,
    now: () => new Date("2026-07-15T12:00:00.000Z"),
    taskIdentityProvider: async () => ({ taskDefinitionArn: taskDefinitionTwo, taskArn: "arn:task/current" }),
  });

  const observation = await coordinator.recordStartup();

  assert.deepEqual(observation, {
    count: 3,
    durable: true,
    loopDetected: true,
    windowMinutes: 15,
    startedAt: "2026-07-15T12:00:00.000Z",
  });
});

test("restart coordination returns the latest ECS stop code reason and exit code", async () => {
  const coordinator = new SlackEventCoordinator(testConfig({
    coordination: {
      deploymentFenceEnabled: true,
      ecsClusterName: "cluster",
      ecsServiceName: "service",
    },
  }), {
    ecs: new StoppedTaskEcs(),
    now: () => new Date("2026-07-15T12:00:00.000Z"),
  });

  const stopped = await coordinator.recentStoppedTask();

  assert.equal(stopped?.stopCode, "EssentialContainerExited");
  assert.equal(stopped?.stoppedReason, "Essential container in task exited");
  assert.equal(stopped?.containerReason, "OutOfMemoryError");
  assert.equal(stopped?.exitCode, 137);
});

class FakeDynamo {
  private readonly keys = new Set<string>();

  async send(command: any): Promise<unknown> {
    const item = command.input.Item;
    const key = `${item.pk}#${item.sk}`;
    if (this.keys.has(key)) {
      const error = new Error("conditional check failed");
      error.name = "ConditionalCheckFailedException";
      throw error;
    }
    this.keys.add(key);
    return {};
  }
}

class FakeEcs {
  constructor(
    private readonly primaryTaskDefinition: string,
    private readonly primaryRunningCount: number,
  ) {}

  async send(): Promise<unknown> {
    return {
      services: [
        {
          deployments: [
            {
              status: "PRIMARY",
              taskDefinition: this.primaryTaskDefinition,
              runningCount: this.primaryRunningCount,
            },
          ],
        },
      ],
    };
  }
}

class ReleaseDynamo {
  readonly getKeys: string[] = [];
  readonly updates: any[] = [];

  constructor(
    private readonly receipt: any,
    private readonly startupItems: any[] = [],
  ) {}

  async send(command: any): Promise<unknown> {
    const name = command.constructor.name;
    if (name === "GetCommand") {
      this.getKeys.push(command.input.Key.sk);
      if (command.input.Key.sk === "current") {
        return { Item: { version: this.receipt.version, updatedAt: this.receipt.updatedAt } };
      }
      return { Item: this.receipt };
    }
    if (name === "UpdateCommand") {
      this.updates.push(command.input);
      return {};
    }
    if (name === "QueryCommand") return { Items: this.startupItems };
    if (name === "PutCommand") return {};
    throw new Error(`Unexpected command ${name}`);
  }
}

class StoppedTaskEcs {
  async send(command: any): Promise<unknown> {
    if (command.constructor.name === "ListTasksCommand") return { taskArns: ["arn:task/older", "arn:task/latest"] };
    if (command.constructor.name === "DescribeTasksCommand") {
      return {
        tasks: [
          {
            taskArn: "arn:task/older",
            stoppedAt: new Date("2026-07-15T11:50:00.000Z"),
            stopCode: "ServiceSchedulerInitiated",
          },
          {
            taskArn: "arn:task/latest",
            stoppedAt: new Date("2026-07-15T11:59:00.000Z"),
            stopCode: "EssentialContainerExited",
            stoppedReason: "Essential container in task exited",
            containers: [{ name: "companion", reason: "OutOfMemoryError", exitCode: 137 }],
          },
        ],
      };
    }
    throw new Error(`Unexpected command ${command.constructor.name}`);
  }
}

function releaseItem(): any {
  return {
    schemaVersion: 1,
    recordType: "companion_release_receipt",
    version: "sha-1234567",
    previousVersion: "sha-previous",
    commitSha: "1234567890abcdef",
    commitSubject: "Join deployment and runtime evidence (#153)",
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
    deployRunUrl: "https://github.com/WriterInternal/cerebro-slack-companion/actions/runs/123",
    startedAt: "2026-07-15T12:00:00.000Z",
    updatedAt: "2026-07-15T12:00:00.000Z",
    threadTsByChannel: {},
    notificationClaims: {},
    notifications: {},
  };
}
