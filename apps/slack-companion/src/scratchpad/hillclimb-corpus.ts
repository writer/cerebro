import type { SlackWorkingStateEvalCaseV1 } from "./hillclimb.js";

function continuationCase(
  caseRef: string,
  partition: "held_out" | "shadow",
  rootRequest: string,
  currentRequest: string,
  requiredFragment: string,
  blocker: string,
): SlackWorkingStateEvalCaseV1 {
  return Object.freeze({
    case_ref: caseRef,
    current_request: currentRequest,
    forbidden_context: Object.freeze([]),
    partition,
    prior_turns: Object.freeze([Object.freeze({
      blocker,
      outcome: "blocked" as const,
      request: rootRequest,
    })]),
    required_context: Object.freeze([
      requiredFragment,
      "Last outcome: blocked.",
      `Last blocker: ${blocker}.`,
    ]),
    schema_version: "slack-working-state-eval-case/v1" as const,
  });
}

/**
 * Public-safe abstractions of observed continuation failures. Held-out cases
 * preserve the failure shape without workspace names, people, ids, or data.
 * Shadow cases use separately written tasks and wording.
 */
export const SLACK_WORKING_STATE_HILLCLIMB_CORPUS: readonly SlackWorkingStateEvalCaseV1[] =
  Object.freeze([
    continuationCase(
      "case://held-out/ranked-projects",
      "held_out",
      "Rank three remediation projects using current evidence.",
      "Keep going.",
      "Rank three remediation projects",
      "The evidence query timed out",
    ),
    continuationCase(
      "case://held-out/next-risk",
      "held_out",
      "Identify the most material risk and support it with current evidence.",
      "Give me another.",
      "Identify the most material risk",
      "The source check did not finish",
    ),
    continuationCase(
      "case://held-out/control-summary",
      "held_out",
      "Summarize the control gaps for this service.",
      "Continue until completion.",
      "Summarize the control gaps",
      "The graph request exceeded its budget",
    ),
    continuationCase(
      "case://held-out/plan-comparison",
      "held_out",
      "Compare the two proposed response plans.",
      "Proceed.",
      "Compare the two proposed response plans",
      "One evidence source was unavailable",
    ),
    continuationCase(
      "case://held-out/source-health",
      "held_out",
      "Report connector health for Source A.",
      "Try again.",
      "Report connector health for Source A",
      "The connector status request timed out",
    ),
    continuationCase(
      "case://held-out/finding-owners",
      "held_out",
      "List the owners of the open priority findings.",
      "Finish the request.",
      "List the owners of the open priority findings",
      "The owner lookup was interrupted",
    ),
    continuationCase(
      "case://held-out/evidence-ranking",
      "held_out",
      "Rank the response options by verified impact.",
      "Resume.",
      "Rank the response options by verified impact",
      "The impact query did not complete",
    ),
    Object.freeze({
      case_ref: "case://held-out/repeated-continuation",
      current_request: "Keep working.",
      forbidden_context: Object.freeze([]),
      partition: "held_out",
      prior_turns: Object.freeze([
        Object.freeze({
          outcome: "completed" as const,
          request: "Build a prioritized remediation sequence.",
        }),
        Object.freeze({
          blocker: "The first attempt timed out",
          outcome: "blocked" as const,
          request: "Keep going.",
        }),
        Object.freeze({
          blocker: "The second attempt timed out",
          outcome: "blocked" as const,
          request: "Continue until completion.",
        }),
      ]),
      required_context: Object.freeze([
        "Build a prioritized remediation sequence.",
        "Last outcome: blocked.",
        "Last blocker: The second attempt timed out.",
      ]),
      schema_version: "slack-working-state-eval-case/v1",
    }),
    Object.freeze({
      case_ref: "case://held-out/expired-state",
      current_request: "Start a separate assessment.",
      forbidden_context: Object.freeze(["Assess the retired service."]),
      partition: "held_out",
      prior_turns: Object.freeze([Object.freeze({
        outcome: "completed" as const,
        request: "Assess the retired service.",
      })]),
      read_after_ms: 8 * 24 * 60 * 60 * 1_000,
      required_context: Object.freeze([]),
      schema_version: "slack-working-state-eval-case/v1",
    }),
    Object.freeze({
      case_ref: "case://held-out/bounded-eviction",
      current_request: "Continue the latest task.",
      forbidden_context: Object.freeze(["Review obsolete task zero."]),
      partition: "held_out",
      prior_turns: Object.freeze([
        Object.freeze({
          outcome: "completed" as const,
          request: "Review obsolete task zero.",
        }),
        Object.freeze({
          outcome: "completed" as const,
          request: "Review active task one.",
        }),
        Object.freeze({
          outcome: "completed" as const,
          request: "Review active task two.",
        }),
        Object.freeze({
          outcome: "completed" as const,
          request: "Review active task three.",
        }),
      ]),
      required_context: Object.freeze([
        "Review active task one.",
        "Review active task two.",
        "Review active task three.",
      ]),
      schema_version: "slack-working-state-eval-case/v1",
    }),
    continuationCase(
      "case://shadow/ranked-actions",
      "shadow",
      "Return four containment actions ordered by expected risk reduction.",
      "Carry on.",
      "Return four containment actions",
      "The risk calculation stopped early",
    ),
    continuationCase(
      "case://shadow/next-exposure",
      "shadow",
      "Find the largest current exposure and cite its supporting records.",
      "Show the next one.",
      "Find the largest current exposure",
      "The record search was incomplete",
    ),
    continuationCase(
      "case://shadow/policy-gaps",
      "shadow",
      "Explain the unresolved policy gaps for this workload.",
      "Complete that.",
      "Explain the unresolved policy gaps",
      "The policy evidence fetch timed out",
    ),
    continuationCase(
      "case://shadow/option-review",
      "shadow",
      "Review the available mitigation options against the stated constraints.",
      "Go ahead.",
      "Review the available mitigation options",
      "A required source was temporarily unavailable",
    ),
    continuationCase(
      "case://shadow/collector-status",
      "shadow",
      "Check collection health for Feed B.",
      "Retry it.",
      "Check collection health for Feed B",
      "The collection status call exceeded its deadline",
    ),
    continuationCase(
      "case://shadow/accountability",
      "shadow",
      "Map each unresolved action to its accountable role.",
      "Continue the work.",
      "Map each unresolved action",
      "The accountability query did not finish",
    ),
    continuationCase(
      "case://shadow/impact-order",
      "shadow",
      "Order the proposed fixes by measured impact.",
      "Pick this back up.",
      "Order the proposed fixes by measured impact",
      "The measurement lookup was interrupted",
    ),
    Object.freeze({
      case_ref: "case://shadow/repeated-retry",
      current_request: "Take the next step.",
      forbidden_context: Object.freeze([]),
      partition: "shadow",
      prior_turns: Object.freeze([
        Object.freeze({
          outcome: "completed" as const,
          request: "Produce an evidence-backed recovery plan.",
        }),
        Object.freeze({
          blocker: "The initial source check timed out",
          outcome: "blocked" as const,
          request: "Continue.",
        }),
        Object.freeze({
          blocker: "The retry also timed out",
          outcome: "blocked" as const,
          request: "Keep going until done.",
        }),
      ]),
      required_context: Object.freeze([
        "Produce an evidence-backed recovery plan.",
        "Last outcome: blocked.",
        "Last blocker: The retry also timed out.",
      ]),
      schema_version: "slack-working-state-eval-case/v1",
    }),
    Object.freeze({
      case_ref: "case://shadow/expired-state",
      current_request: "Begin a new independent review.",
      forbidden_context: Object.freeze(["Inspect the decommissioned collector."]),
      partition: "shadow",
      prior_turns: Object.freeze([Object.freeze({
        outcome: "completed" as const,
        request: "Inspect the decommissioned collector.",
      })]),
      read_after_ms: 8 * 24 * 60 * 60 * 1_000,
      required_context: Object.freeze([]),
      schema_version: "slack-working-state-eval-case/v1",
    }),
    Object.freeze({
      case_ref: "case://shadow/bounded-eviction",
      current_request: "Resume the current sequence.",
      forbidden_context: Object.freeze(["Trace superseded sequence zero."]),
      partition: "shadow",
      prior_turns: Object.freeze([
        Object.freeze({
          outcome: "completed" as const,
          request: "Trace superseded sequence zero.",
        }),
        Object.freeze({
          outcome: "completed" as const,
          request: "Trace current sequence one.",
        }),
        Object.freeze({
          outcome: "completed" as const,
          request: "Trace current sequence two.",
        }),
        Object.freeze({
          outcome: "completed" as const,
          request: "Trace current sequence three.",
        }),
      ]),
      required_context: Object.freeze([
        "Trace current sequence one.",
        "Trace current sequence two.",
        "Trace current sequence three.",
      ]),
      schema_version: "slack-working-state-eval-case/v1",
    }),
  ]);
