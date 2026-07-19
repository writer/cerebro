import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  hasSecuritySignal,
  hasSpecificText,
  isGenericTriageText,
} from "../src/triage/alert-triage-signals.js";
import {
  channelPolicyFor,
  minimumConfidenceForPolicy,
  policyAllowsPost,
  policyAllowsTriage,
  policyContextLine,
  type TriageChannelPolicyInputV1,
  type TriageChannelPolicyV1,
} from "../src/triage/channel-policy.js";
import type { AlertTriageClassificationV1 } from "../src/triage/contracts.js";

const signalTokens = [
  "admin",
  "anomaly",
  "attack",
  "credential",
  "critical",
  "cve",
  "exfil",
  "exposure",
  "high",
  "malware",
  "mfa",
  "okta",
  "phishing",
  "privilege",
  "root",
  "secret",
  "suspicious",
  "token",
  "vulnerability",
] as const;

const genericTriagePhrases = [
  "not enough context",
  "needs more context",
  "review the source alert fields",
  "check related cerebro findings",
  "rerun triage",
  "no response action is needed",
  "does not contain enough verified context",
  "graph reasoning was unavailable",
  "generic advice",
] as const;

describe("portable alert-triage signals", () => {
  test("preserves every security signal token and word boundary", () => {
    for (const token of signalTokens) {
      assert.equal(hasSecuritySignal(`Observed ${token} activity.`), true, token);
      assert.equal(hasSecuritySignal(token.toUpperCase()), true, token);
    }
    assert.equal(hasSecuritySignal("administrator activity"), false);
    assert.equal(hasSecuritySignal("tokenized output"), false);
    assert.equal(hasSecuritySignal("routine maintenance"), false);
  });

  test("preserves every generic triage phrase", () => {
    for (const phrase of genericTriagePhrases) {
      assert.equal(isGenericTriageText(`Result: ${phrase}.`), true, phrase);
      assert.equal(isGenericTriageText(phrase.toUpperCase()), true, phrase);
    }
    assert.equal(isGenericTriageText("Confirm the accountable owner."), false);
  });

  test("requires a non-generic trimmed item with at least twelve characters", () => {
    assert.equal(hasSpecificText(["short text"]), false);
    assert.equal(hasSpecificText(["  not enough context for this alert  "]), false);
    assert.equal(hasSpecificText(["generic advice", "  Confirm the owner before rollout.  "]), true);
  });
});

describe("portable triage channel policy", () => {
  test("selects explicit, watched, and strict channel policies in order", () => {
    const input = policyInput({
      channel_policies: new Map([
        ["channel-explicit", "quiet"],
        ["channel-overridden", "eager"],
      ]),
      triage_channel_ids: new Set(["channel-watch", "channel-overridden"]),
    });

    assert.equal(channelPolicyFor(input, undefined), "strict");
    assert.equal(channelPolicyFor(input, ""), "strict");
    assert.equal(channelPolicyFor(input, "channel-explicit"), "quiet");
    assert.equal(channelPolicyFor(input, "channel-overridden"), "eager");
    assert.equal(channelPolicyFor(input, "channel-watch"), "watch");
    assert.equal(channelPolicyFor(input, "channel-other"), "strict");
  });

  test("preserves confidence floors, eager reduction, and watch threshold", () => {
    assert.deepEqual(confidenceByPolicy(0.5), {
      eager: 0.35,
      quiet: 0.7,
      strict: 0.85,
      watch: 0.5,
    });
    assert.deepEqual(confidenceByPolicy(0.1), {
      eager: 0,
      quiet: 0.7,
      strict: 0.85,
      watch: 0.1,
    });
    assert.deepEqual(confidenceByPolicy(0.9), {
      eager: 0.75,
      quiet: 0.9,
      strict: 0.9,
      watch: 0.9,
    });
  });

  test("always admits eager and watch messages", () => {
    assert.equal(policyAllowsTriage({}, "eager"), true);
    assert.equal(policyAllowsTriage({}, "watch"), true);
  });

  test("admits security signals under strict and quiet policies", () => {
    assert.equal(policyAllowsTriage({ text: "Critical credential exposure" }, "strict"), true);
    assert.equal(policyAllowsTriage({ text: "Critical credential exposure" }, "quiet"), true);
  });

  test("preserves every bot-message admission phrase", () => {
    const phrases = [
      "alert",
      "incident",
      "finding",
      "runtime",
      "deploy",
      "deployment",
      "rollback",
      "failed",
      "failure",
      "blocked",
      "policy",
      "approval",
      "pull request",
      "pr #42",
      "ci",
      "check run",
      "sync failed",
    ];
    for (const text of phrases) {
      assert.equal(policyAllowsTriage({ bot_id: "bot", text }, "strict"), true, text);
    }
    assert.equal(
      policyAllowsTriage({ subtype: "bot_message", text: "deployment" }, "strict"),
      true,
    );
    assert.equal(policyAllowsTriage({ text: "deployment" }, "strict"), false);
  });

  test("admits only matching quiet-policy thread replies", () => {
    const phrases = [
      "false positive",
      "what evidence",
      "why",
      "owner",
      "admin",
      "action",
      "actions",
      "merged",
      "shipped",
      "fixed",
      "resolved",
      "blocked",
      "failed",
    ];
    for (const text of phrases) {
      assert.equal(
        policyAllowsTriage({ text, thread_ts: "thread-1", ts: "reply-1" }, "quiet"),
        true,
        text,
      );
    }
    assert.equal(policyAllowsTriage({ text: "what evidence" }, "quiet"), false);
    assert.equal(
      policyAllowsTriage({ text: "what evidence", thread_ts: "message-1", ts: "message-1" }, "quiet"),
      false,
    );
    assert.equal(
      policyAllowsTriage({ text: "routine update", thread_ts: "thread-1", ts: "reply-1" }, "quiet"),
      false,
    );
  });

  test("maps frozen post gates to the current public classifications", () => {
    const expected: Record<TriageChannelPolicyV1, Record<AlertTriageClassificationV1, boolean>> = {
      eager: { actionable: true, needs_context: true, non_actionable: true },
      quiet: { actionable: true, needs_context: true, non_actionable: false },
      strict: { actionable: true, needs_context: false, non_actionable: false },
      watch: { actionable: true, needs_context: true, non_actionable: true },
    };
    for (const [policy, decisions] of Object.entries(expected)) {
      for (const [classification, allowed] of Object.entries(decisions)) {
        assert.equal(
          policyAllowsPost(
            classification as AlertTriageClassificationV1,
            policy as TriageChannelPolicyV1,
          ),
          allowed,
          `${policy}:${classification}`,
        );
      }
    }
  });

  test("preserves each host-facing policy instruction", () => {
    assert.equal(
      policyContextLine("strict"),
      "Channel policy: strict. Speak only for high-confidence security issues with verified evidence.",
    );
    assert.equal(
      policyContextLine("quiet"),
      "Channel policy: quiet. Speak only when the reply changes an investigation, deploy, or security decision.",
    );
    assert.equal(
      policyContextLine("eager"),
      "Channel policy: eager. Review more messages, but still post only concrete, evidence-backed help.",
    );
    assert.equal(
      policyContextLine("watch"),
      "Channel policy: watch. Review configured signals and post only when useful.",
    );
  });
});

function policyInput(
  overrides: Partial<TriageChannelPolicyInputV1> = {},
): TriageChannelPolicyInputV1 {
  return {
    channel_policies: new Map(),
    minimum_confidence: 0.5,
    triage_channel_ids: new Set(),
    ...overrides,
  };
}

function confidenceByPolicy(minimumConfidence: number): Record<TriageChannelPolicyV1, number> {
  const input = policyInput({ minimum_confidence: minimumConfidence });
  return {
    eager: minimumConfidenceForPolicy(input, "eager"),
    quiet: minimumConfidenceForPolicy(input, "quiet"),
    strict: minimumConfidenceForPolicy(input, "strict"),
    watch: minimumConfidenceForPolicy(input, "watch"),
  };
}
