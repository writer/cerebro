import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { assessDangerousIntent } from "../../security/safety.js";
import {
  limit,
  normalizeMemoryKind,
  normalizePromotionState,
  normalizeStalenessPolicy,
  stringList,
} from "./normalizers.js";
import { boundInput, resilientDetails, runResilient } from "./resilient-tool.js";
import type { SecurityToolDeps } from "./types.js";
import { toolResult } from "./tool-result.js";

export function createMemoryTools(deps: SecurityToolDeps): AgentTool[] {
  const memorySearchParams = Type.Object({
    query: Type.String(),
    limit: Type.Optional(Type.Number()),
  });
  const memoryReadParams = Type.Object({
    query: Type.String(),
    mode: Type.Optional(Type.String()),
    kinds: Type.Optional(Type.Array(Type.String())),
    channel_id: Type.Optional(Type.String()),
    since: Type.Optional(Type.String()),
    limit: Type.Optional(Type.Number()),
  });
  const sessionRecallParams = Type.Object({
    query: Type.Optional(Type.String()),
    kinds: Type.Optional(Type.Array(Type.String())),
    channel_id: Type.Optional(Type.String()),
    since: Type.Optional(Type.String()),
    limit: Type.Optional(Type.Number()),
  });
  const memoryPromoteParams = Type.Object({
    id: Type.Optional(Type.String()),
    topic: Type.Optional(Type.String()),
  });
  const memoryHygieneParams = Type.Object({
    dry_run: Type.Optional(Type.Boolean()),
  });
  const workingMemoryReadParams = Type.Object({
    target: Type.Optional(Type.String()),
  });
  const workingMemoryWriteParams = Type.Object({
    action: Type.String(),
    target: Type.Optional(Type.String()),
    content: Type.Optional(Type.String()),
    old_text: Type.Optional(Type.String()),
  });
  const learningDocsReadParams = Type.Object({
    target: Type.Optional(Type.String()),
  });
  const learningDocsWriteParams = Type.Object({
    action: Type.Optional(Type.String()),
    target: Type.String(),
    topic: Type.String(),
    summary: Type.Optional(Type.String()),
    details: Type.Optional(Type.String()),
    tags: Type.Optional(Type.Array(Type.String())),
    source: Type.Optional(Type.String()),
  });
  const companyLibrarySearchParams = Type.Object({
    query: Type.String(),
    limit: Type.Optional(Type.Number()),
  });
  const companyLibraryReadParams = Type.Object({
    id_or_domain: Type.String(),
  });
  const memoryWriteParams = Type.Object({
    kind: Type.String(),
    topic: Type.String(),
    summary: Type.String(),
    details: Type.Optional(Type.String()),
    tags: Type.Optional(Type.Array(Type.String())),
    confidence: Type.Optional(Type.Number()),
    scope: Type.Optional(Type.String()),
    verified_by: Type.Optional(Type.Array(Type.String())),
    source_artifacts: Type.Optional(Type.Array(Type.String())),
    staleness_policy: Type.Optional(Type.String()),
    promotion_state: Type.Optional(Type.String()),
  });

  return [
    {
      name: "security_working_memory_read",
      label: "Security working memory read",
      description: "Read Cerebro's bounded MEMORY.md and TEAM.md working-memory files that are loaded into each agent prompt.",
      parameters: workingMemoryReadParams,
      execute: async (_toolCallId, params) => {
        const args = params as { target?: string };
        return toolResult({ memories: deps.memory.readWorkingMemory(args.target) });
      },
    },
    {
      name: "security_working_memory_write",
      label: "Security working memory write",
      description: "Curate Cerebro's durable working-memory files. Actions: add, replace, remove. Targets: memory for operational/security lessons, team for channel/team preferences. Store compact explicit observations only; never store secrets, raw logs, transcripts, or hidden reasoning.",
      parameters: workingMemoryWriteParams,
      execute: async (_toolCallId, params) => {
        const args = params as { action?: string; target?: string; content?: string; old_text?: string };
        const safety = assessDangerousIntent(args.content);
        if (!safety.allowed) {
          return toolResult({
            success: false,
            error: "unsafe_memory_write",
            category: safety.category,
            message: safety.refusal,
          });
        }
        return toolResult(deps.memory.writeWorkingMemory({
          action: args.action,
          target: args.target,
          content: args.content,
          oldText: args.old_text,
        }));
      },
    },
    {
      name: "security_learning_docs_read",
      label: "Security learning docs read",
      description: "Read Cerebro's curated markdown learning docs. Targets: security-knowledge, normal-patterns, runbook, investigations, skill-improvements. Use for stable lessons learned across days, not raw Slack history.",
      parameters: learningDocsReadParams,
      execute: async (_toolCallId, params) => {
        const args = params as { target?: string };
        return toolResult({ docs: deps.memory.readLearningDocs(args.target) });
      },
    },
    {
      name: "security_learning_docs_write",
      label: "Security learning docs write",
      description: "Update Cerebro's curated markdown learning docs. Actions: upsert, remove. Targets: security-knowledge, normal-patterns, runbook, investigations, skill-improvements. Store stable non-secret lessons only; do not store raw logs, transcripts, credentials, or hidden reasoning.",
      parameters: learningDocsWriteParams,
      execute: async (_toolCallId, params) => {
        const args = params as { action?: string; target?: string; topic?: string; summary?: string; details?: string; tags?: string[]; source?: string };
        const safety = assessDangerousIntent([args.topic ?? "", args.summary ?? "", args.details ?? ""].join("\n"));
        if (!safety.allowed) {
          return toolResult({
            success: false,
            error: "unsafe_learning_doc_write",
            category: safety.category,
            message: safety.refusal,
          });
        }
        return toolResult(deps.memory.writeLearningDocs({
          action: args.action,
          target: args.target,
          topic: args.topic,
          summary: args.summary,
          details: args.details,
          tags: args.tags,
          source: args.source,
        }));
      },
    },
    {
      name: "company_library_search",
      label: "Company library search",
      description: "Search Cerebro's compounded company library for operating procedures, ownership, decisions, exceptions, contradictions, and cross-domain theses. Results are sourced historical candidates; verify change-prone claims against current systems before acting.",
      parameters: companyLibrarySearchParams,
      execute: async (_toolCallId, params) => {
        const args = params as { query: string; limit?: number };
        const records = await deps.memory.companyLibrary.search(boundInput(args.query).text, limit(args.limit, 12));
        return toolResult({
          records: records.filter((record) => companyLibraryVisible(record.channelIds, deps.requestContext?.channelId)),
          note: "Library claims are candidate operating knowledge with Slack source receipts. Reverify current owners, production state, access, and policy before acting.",
        });
      },
    },
    {
      name: "company_library_read",
      label: "Company library read",
      description: "Read one company-library dossier or thesis by record id or domain key, including its claims, procedures, ownership, contradictions, open questions, and source receipts.",
      parameters: companyLibraryReadParams,
      execute: async (_toolCallId, params) => {
        const args = params as { id_or_domain: string };
        const record = await deps.memory.companyLibrary.read(args.id_or_domain);
        return toolResult({ record: record && companyLibraryVisible(record.channelIds, deps.requestContext?.channelId) ? record : undefined });
      },
    },
    {
      name: "security_memory_read",
      label: "Security memory read",
      description: "Read security memory by mode. Use mode=search for keyword memory, mode=recall for prior answers and diagnostics, or mode=intelligence for memory graph and lineage diagnostics.",
      parameters: memoryReadParams,
      execute: async (_toolCallId, params) => {
        const args = params as MemoryReadArgs;
        return toolResult(await memoryReadDetails(deps, args));
      },
    },
    {
      name: "security_memory_search",
      label: "Security memory search",
      description: "Search durable security memory for normal patterns, prior investigations, runbook notes, and prior answers. Pair stable results with security_learning_docs_read when the answer needs accumulated runbook or normal-pattern context.",
      parameters: memorySearchParams,
      execute: async (_toolCallId, params) => {
        const args = params as { query: string; limit?: number };
        return toolResult(await memoryReadDetails(deps, args, "search"));
      },
    },
    {
      name: "security_session_recall",
      label: "Security session recall",
      description: "Search Cerebro's prior Slack answers, alert triage outcomes, investigation notes, runbook notes, and normal patterns with trust, freshness, coverage, conflict, graph, and lineage-DAG diagnostics. Use when a question may have prior context, when an alert looks recurring, or before repeating a past conclusion. This is conversation memory, not proof of the current graph state; pair it with live Cerebro or Slack evidence before making present-tense security claims.",
      parameters: sessionRecallParams,
      execute: async (_toolCallId, params) => {
        const args = params as MemoryReadArgs;
        return toolResult(await memoryReadDetails(deps, args, "recall"));
      },
    },
    {
      name: "security_memory_intelligence",
      label: "Security memory intelligence",
      description: "Build a bounded memory graph and lineage DAG for a security question. Use this before relying on memory for investigation planning, repeated finding triage, self-improvement, or contradictory prior context. Inspect warnings, missing entities, conflicts, source artifacts, verifiers, trust scores, and DAG edges before deciding what to verify next.",
      parameters: sessionRecallParams,
      execute: async (_toolCallId, params) => {
        const args = params as MemoryReadArgs;
        return toolResult(await memoryReadDetails(deps, args, "intelligence"));
      },
    },
    {
      name: "security_memory_write",
      label: "Security memory write",
      description: "Persist a concise non-secret security observation for future Slack triage. Use access_context, asset_context, connector_context, detection_context, exception_context, owner_context, and severity_context for source-backed Infosec knowledge; use runbook_note, investigation_note, normal_pattern, team_context, explicit_memory, encounter_story, or skill_improvement for learned operating context. Explicit tool writes are promoted by default; set promotion_state=candidate or transient for unverified notes. Promoted durable context also updates markdown learning docs.",
      parameters: memoryWriteParams,
      execute: async (_toolCallId, params) => {
        const args = params as {
          kind: string;
          topic: string;
          summary: string;
          details?: string;
          tags?: string[];
          confidence?: number;
          scope?: string;
          verified_by?: string[];
          source_artifacts?: string[];
          staleness_policy?: string;
          promotion_state?: string;
        };
        const safety = assessDangerousIntent([args.topic, args.summary, args.details ?? ""].join("\n"));
        if (!safety.allowed) {
          return toolResult({
            stored: false,
            error: "unsafe_memory_write",
            category: safety.category,
            message: safety.refusal,
          });
        }
        const kind = normalizeMemoryKind(args.kind);
        const promotionState = normalizePromotionState(args.promotion_state) ?? "promoted";
        const record = await deps.memory.remember({
          kind,
          topic: args.topic,
          summary: args.summary,
          details: args.details,
          tags: args.tags,
          confidence: args.confidence,
          sourceKind: "tool",
          scope: args.scope,
          verifiedBy: stringList(args.verified_by),
          sourceArtifacts: stringList(args.source_artifacts),
          stalenessPolicy: normalizeStalenessPolicy(args.staleness_policy) ?? (promotionState === "promoted" ? "durable" : undefined),
          promotionState,
        });
        return toolResult({ stored: Boolean(record), record });
      },
    },
    {
      name: "security_memory_promote",
      label: "Security memory promote",
      description: "Promote one verified memory record into the curated learning docs by id or a unique topic substring. Use after source evidence confirms a reusable runbook, normal pattern, investigation lesson, team context, or skill-improvement note.",
      parameters: memoryPromoteParams,
      execute: async (_toolCallId, params) => {
        const args = params as { id?: string; topic?: string };
        return toolResult(await deps.memory.promoteToLearningDocs({
          id: args.id,
          topic: args.topic,
        }));
      },
    },
    {
      name: "security_memory_hygiene",
      label: "Security memory hygiene",
      description: "Review or expire stale transient memories and duplicate records. Defaults to dry_run=true; set dry_run=false only for an explicit cleanup request or scheduled maintenance.",
      parameters: memoryHygieneParams,
      execute: async (_toolCallId, params) => {
        const args = params as { dry_run?: boolean };
        return toolResult(await deps.memory.runHygiene({ dryRun: args.dry_run ?? true }));
      },
    },
  ];
}

type MemoryReadMode = "search" | "recall" | "intelligence";

interface MemoryReadArgs {
  query?: string;
  mode?: string;
  kinds?: string[];
  channel_id?: string;
  since?: string;
  limit?: number;
}

async function memoryReadDetails(
  deps: SecurityToolDeps,
  args: MemoryReadArgs,
  modeOverride?: MemoryReadMode,
): Promise<Record<string, unknown>> {
  const mode = modeOverride ?? normalizeMemoryReadMode(args.mode);
  const bounded = boundInput(args.query ?? "");
  const resultLimit = limit(args.limit, deps.config.learning.maxSearchResults);
  const recallInput = () => ({
    query: args.query === undefined ? undefined : bounded.text,
    kinds: args.kinds?.map(normalizeMemoryKind),
    channelId: args.channel_id,
    ...(deps.requestContext?.channelId ? { audienceChannelId: deps.requestContext.channelId } : {}),
    since: args.since,
    limit: resultLimit,
  });
  const search = async () => ({
    mode: "search",
    memories: await deps.memory.search(bounded.text, resultLimit, deps.requestContext?.channelId),
  });

  const result = await runResilient<Record<string, unknown>>({
    name: `security_memory_read[${mode}]`,
    run: async () => {
      if (mode === "search") return search();
      const recalled = await deps.memory.recallWithDiagnostics(recallInput());
      if (mode === "recall") {
        return {
          mode,
          memories: recalled.memories,
          diagnostics: recalled.diagnostics,
          note: "These are Cerebro's prior notes and Slack-session summaries. Verify current state with graph, finding, runtime, or Slack source tools before treating a recalled conclusion as still true.",
        };
      }
      return {
        mode,
        memories: recalled.memories,
        diagnostics: recalled.diagnostics,
        memory_graph: jsonClone(recalled.diagnostics.memoryGraph),
        lineage_dag: jsonClone(recalled.diagnostics.lineageDag),
        warnings: recalled.diagnostics.warnings,
        note: "Use this graph as memory structure. Verify current state with Cerebro graph, finding, runtime, EvidenceCAS, or Slack source tools before making current-state claims.",
      };
    },
    fallbacks: mode === "search"
      ? []
      : [{
          name: "memory_search",
          run: async () => ({
            ...await search(),
            note: "Memory diagnostics were unavailable, so this returned keyword memory results.",
          }),
        }],
  });

  return resilientDetails(result, {
    input_truncated: bounded.truncated || undefined,
    degraded: result.degraded || bounded.truncated || undefined,
  });
}

function normalizeMemoryReadMode(mode: string | undefined): MemoryReadMode {
  if (mode === "recall" || mode === "intelligence") return mode;
  return "search";
}

function companyLibraryVisible(channelIds: string[] | undefined, audienceChannelId?: string): boolean {
  return !channelIds || channelIds.length === 0 || Boolean(audienceChannelId && channelIds.every((channelId) => channelId === audienceChannelId));
}

function jsonClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
