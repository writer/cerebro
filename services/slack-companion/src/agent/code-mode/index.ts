import type { AgentTool, AgentToolResult } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { fork, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { AgentToolCatalog } from "../tool-catalog.js";
import { boundedToolDetails, hasUsablePartialToolEvidence, objectValue, toolResult } from "../tools/tool-result.js";
import {
  securityAgentToolMetadata,
  securityAgentToolMetadataIsExplicit,
} from "../tools/tool-metadata.js";
import { annotateSpan, telemetryEvent, withTelemetrySpan } from "../../telemetry.js";
import type {
  SandboxExecuteMessage,
  SandboxResultMessage,
  SandboxToParentMessage,
  SandboxToolCallMessage,
  SandboxToolResultMessage,
} from "./protocol.js";

const CODE_MODE_TOOL_NAMES = new Set(["cerebro_tool_search", "cerebro_execute"]);
const MAX_NESTED_ARGUMENT_BYTES = 20_000;

export interface CreateCodeModeToolsOptions {
  baseTools: AgentTool[];
  additionalReadOnlyToolNames?: ReadonlySet<string>;
  beforeToolCall?: (toolName: string) => Promise<void> | void;
  afterToolCall?: (toolName: string, isError: boolean) => Promise<void> | void;
  maxToolCalls: number;
  maxSideEffectCalls?: number;
  timeoutMs: number;
  memoryLimitBytes: number;
  maxScriptBytes: number;
  maxOutputBytes: number;
  allowedToolNames: () => ReadonlySet<string>;
}

type CodeModeOutcome = "completed" | "failed" | "blocked" | "timed_out" | "terminated" | "outcome_unknown";
type LimitClass = "deadline" | "policy" | "protocol" | "tool_limit" | "side_effect_limit" | "output_limit" | "memory_limit" | "guest_error" | "child_exit" | "none";

interface NestedCallLedgerEntry {
  name: string;
  status: "blocked" | "completed" | "failed" | "started";
  side_effect: boolean;
  side_effect_outcome?: "not_started";
  error_code?: string;
  evidence_receipt?: string;
}

interface SandboxExecution {
  outcome: CodeModeOutcome;
  output?: unknown;
  terminationReason: LimitClass;
  childExitClass: "clean" | "error" | "signal" | "spawn_error";
  outputTruncated: boolean;
  toolCallCount: number;
  sideEffectCallCount: number;
  retryAllowed: boolean;
  nestedCalls: NestedCallLedgerEntry[];
}

export function createCodeModeTools(options: CreateCodeModeToolsOptions): AgentTool[] {
  const limits = normalizeLimits(options);
  const catalog = new AgentToolCatalog(options.baseTools);
  const searchParameters = Type.Object({
    query: Type.Optional(Type.String({ maxLength: 240 })),
    limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 20 })),
  });
  const executeParameters = Type.Object({
    program: Type.String({ minLength: 1, maxLength: limits.maxScriptBytes }),
    toolset_digest: Type.String({ minLength: 16, maxLength: 96 }),
  });

  const searchTool: AgentTool<typeof searchParameters> = {
    name: "cerebro_tool_search",
    label: "Search Cerebro tools",
    description: "Search the current Slack assistant tool catalog and return compact TypeScript signatures. The returned digest detects catalog drift; it does not grant authority.",
    parameters: searchParameters,
    execute: async (_toolCallId, params) => {
      const allowed = currentAllowedNames(options, catalog);
      const signatures = catalog.searchSignatures({ query: params.query, limit: params.limit ?? 8 })
        .filter((entry) => allowed.has(entry.name));
      return toolResult({
        tools: signatures,
        toolset_digest: catalog.digest(allowed),
        note: "Use only tools selected in the current research plan. The digest checks consistency and does not authorize a call.",
      });
    },
  };

  const executeTool: AgentTool<typeof executeParameters> = {
    name: "cerebro_execute",
    label: "Execute bounded Cerebro code",
    description: [
      "Run one bounded JavaScript program in a fresh isolated QuickJS child.",
      "The program receives a frozen tools object with async functions for registered operations; use await tools.<name>(args) or Promise.all for independent reads, then return a JSON-serializable value.",
      "Every nested call keeps its normal Slack actor, intent, approval, target, budget, telemetry, and evidence checks. At most one side effect is allowed and side effects are serialized.",
    ].join(" "),
    parameters: executeParameters,
    executionMode: "sequential",
    execute: async (toolCallId, params, signal) => withTelemetrySpan("assistant.code.execute", {
      component: "security-assistant",
      operation: "execute",
    }, async (span) => {
      const startedAt = Date.now();
      const allowed = currentAllowedNames(options, catalog);
      const expectedDigest = catalog.digest(allowed);
      if (params.toolset_digest !== expectedDigest) {
        telemetryEvent("assistant.code.blocked", {
          component: "security-assistant",
          operation: "execute",
          "assistant.code.limit_class": "protocol",
        });
        const blocked = blockedExecution("protocol");
        annotateCodeSpan(span, blocked, Date.now() - startedAt);
        return executionToolResult(blocked, limits.maxOutputBytes);
      }
      if (Buffer.byteLength(params.program, "utf8") > limits.maxScriptBytes) {
        telemetryEvent("assistant.code.blocked", {
          component: "security-assistant",
          operation: "execute",
          "assistant.code.limit_class": "output_limit",
        });
        const blocked = blockedExecution("output_limit");
        annotateCodeSpan(span, blocked, Date.now() - startedAt);
        return executionToolResult(blocked, limits.maxOutputBytes);
      }
      if (/\bimport\s*(?:\(|["'])|\bexport\s+/.test(params.program)) {
        telemetryEvent("assistant.code.blocked", {
          component: "security-assistant",
          operation: "execute",
          "assistant.code.limit_class": "protocol",
        });
        const blocked = blockedExecution("protocol");
        annotateCodeSpan(span, blocked, Date.now() - startedAt);
        return executionToolResult(blocked, limits.maxOutputBytes);
      }

      const execution = await runSandboxedProgram({
        requestId: boundedRequestId(toolCallId),
        program: params.program,
        expectedDigest,
        catalog,
        allowed,
        options,
        limits,
        signal,
      });
      annotateCodeSpan(span, execution, Date.now() - startedAt);
      emitCodeExecutionEvent(execution);
      return executionToolResult(execution, limits.maxOutputBytes);
    }, {
      statusForResult: (result) => {
        const outcome = objectValue(result.details)?.outcome;
        return outcome === "completed" ? "completed" : outcome === "blocked" ? "blocked" : "failed";
      },
      errorEventName: "assistant.code.terminated",
    }),
  };

  return [searchTool, executeTool];
}

function normalizeLimits(options: CreateCodeModeToolsOptions) {
  return {
    maxToolCalls: integerInRange(options.maxToolCalls, 1, 24),
    maxSideEffectCalls: integerInRange(options.maxSideEffectCalls ?? 1, 1, 1),
    timeoutMs: integerInRange(options.timeoutMs, 1_000, 120_000),
    memoryLimitBytes: integerInRange(options.memoryLimitBytes, 32 * 1024 * 1024, 256 * 1024 * 1024),
    maxScriptBytes: integerInRange(options.maxScriptBytes, 1_024, 128 * 1024),
    maxOutputBytes: integerInRange(options.maxOutputBytes, 1_024, 512 * 1024),
  };
}

function integerInRange(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`Code Mode limit must be an integer between ${minimum} and ${maximum}.`);
  }
  return value;
}

function currentAllowedNames(options: CreateCodeModeToolsOptions, catalog: AgentToolCatalog): Set<string> {
  return new Set([...options.allowedToolNames()]
    .filter((name) => !CODE_MODE_TOOL_NAMES.has(name) && Boolean(catalog.get(name))));
}

function blockedExecution(reason: LimitClass): SandboxExecution {
  return {
    outcome: "blocked",
    terminationReason: reason,
    childExitClass: "clean",
    outputTruncated: false,
    toolCallCount: 0,
    sideEffectCallCount: 0,
    retryAllowed: true,
    nestedCalls: [],
  };
}

interface RunSandboxInput {
  requestId: string;
  program: string;
  expectedDigest: string;
  catalog: AgentToolCatalog;
  allowed: Set<string>;
  options: CreateCodeModeToolsOptions;
  limits: ReturnType<typeof normalizeLimits>;
  signal?: AbortSignal;
}

async function runSandboxedProgram(input: RunSandboxInput): Promise<SandboxExecution> {
  const child = spawnWorker();
  const abortController = new AbortController();
  const seenCallIds = new Set<string>();
  const nestedCalls: NestedCallLedgerEntry[] = [];
  const activeReads = new Set<Promise<void>>();
  const inFlightCalls = new Set<Promise<void>>();
  let toolCallCount = 0;
  let sideEffectAttemptCount = 0;
  let sideEffectCallCount = 0;
  let sideEffectStarted = false;
  let uncertainSideEffect = false;
  let classifiedNoSideEffectFailure = false;
  let writeQueued = false;
  let releaseWriteGate: (() => void) | undefined;
  let writeGate = Promise.resolve();
  let finalMessage: SandboxResultMessage | undefined;
  let finalHadPendingCalls = false;
  let finalHadPendingSideEffect = false;
  let forcedReason: LimitClass | undefined;
  let brokerLimitReason: LimitClass | undefined;
  let spawnFailed = false;

  const terminate = (reason: LimitClass) => {
    if (!forcedReason) forcedReason = reason;
    abortController.abort();
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  };
  const onAbort = () => terminate("deadline");
  input.signal?.addEventListener("abort", onAbort, { once: true });
  const timeout = setTimeout(() => terminate("deadline"), input.limits.timeoutMs);
  timeout.unref?.();

  const handleToolCall = async (message: SandboxToolCallMessage): Promise<void> => {
    const respond = (payload: Omit<SandboxToolResultMessage, "type" | "requestId" | "callId">) => {
      if (!child.connected) return;
      child.send({ type: "tool_result", requestId: input.requestId, callId: message.callId, ...payload } satisfies SandboxToolResultMessage);
    };
    if (message.requestId !== input.requestId
      || !message.callId.startsWith(`${input.requestId}:`)
      || seenCallIds.has(message.callId)) {
      forcedReason = "protocol";
      respond({ ok: false, error: "Code Mode broker rejected an invalid call id." });
      terminate("protocol");
      return;
    }
    seenCallIds.add(message.callId);
    toolCallCount += 1;
    if (toolCallCount > input.limits.maxToolCalls) {
      nestedCalls.push({ name: boundedToolName(message.name), status: "blocked", side_effect: false });
      respond({ ok: false, error: "Code Mode tool-call limit reached." });
      brokerLimitReason ??= "tool_limit";
      return;
    }
    if (CODE_MODE_TOOL_NAMES.has(message.name) || !input.allowed.has(message.name) || !input.catalog.get(message.name)) {
      nestedCalls.push({ name: boundedToolName(message.name), status: "blocked", side_effect: false });
      respond({ ok: false, error: "Code Mode broker rejected a tool outside the current catalog." });
      brokerLimitReason ??= "policy";
      return;
    }
    const currentAllowed = currentAllowedNames(input.options, input.catalog);
    if (!currentAllowed.has(message.name) || input.catalog.digest(currentAllowed) !== input.expectedDigest) {
      nestedCalls.push({ name: boundedToolName(message.name), status: "blocked", side_effect: false });
      respond({ ok: false, error: "Code Mode broker detected a current-plan or catalog change." });
      brokerLimitReason ??= "protocol";
      return;
    }
    if (Buffer.byteLength(message.argumentsJson, "utf8") > MAX_NESTED_ARGUMENT_BYTES) {
      nestedCalls.push({ name: boundedToolName(message.name), status: "blocked", side_effect: false });
      respond({ ok: false, error: "Code Mode tool arguments exceeded the limit." });
      brokerLimitReason ??= "protocol";
      return;
    }
    let argumentsValue: unknown;
    try {
      argumentsValue = JSON.parse(message.argumentsJson);
    } catch {
      nestedCalls.push({ name: boundedToolName(message.name), status: "blocked", side_effect: false });
      respond({ ok: false, error: "Code Mode tool arguments were not valid JSON." });
      brokerLimitReason ??= "protocol";
      return;
    }
    const validation = input.catalog.validateArguments(message.name, argumentsValue);
    if (!validation.valid || !validation.arguments) {
      nestedCalls.push({ name: message.name, status: "blocked", side_effect: false });
      respond({ ok: false, error: "Code Mode tool arguments did not match the registered schema." });
      brokerLimitReason ??= "protocol";
      return;
    }

    const metadata = securityAgentToolMetadata(message.name);
    if (!securityAgentToolMetadataIsExplicit(message.name) && !input.options.additionalReadOnlyToolNames?.has(message.name)) {
      nestedCalls.push({ name: boundedToolName(message.name), status: "blocked", side_effect: false });
      respond({ ok: false, error: "Code Mode rejected a tool without explicit authority metadata." });
      brokerLimitReason ??= "policy";
      return;
    }
    const isSideEffect = metadata.sideEffect !== "none";
    const ledger: NestedCallLedgerEntry = { name: message.name, status: "started", side_effect: isSideEffect };
    nestedCalls.push(ledger);
    if (isSideEffect) {
      sideEffectAttemptCount += 1;
      if (sideEffectAttemptCount > input.limits.maxSideEffectCalls) {
        ledger.status = "blocked";
        respond({ ok: false, error: "Code Mode permits one side effect per execution." });
        brokerLimitReason ??= "side_effect_limit";
        return;
      }
      writeQueued = true;
      writeGate = new Promise<void>((resolve) => { releaseWriteGate = resolve; });
      await Promise.allSettled([...activeReads]);
    } else if (writeQueued) {
      await writeGate;
    }

    const execute = async () => {
      let failed = false;
      let policyPassed = false;
      let response: Omit<SandboxToolResultMessage, "type" | "requestId" | "callId"> = {
        ok: false,
        error: "Nested tool execution failed.",
      };
      try {
        await input.options.beforeToolCall?.(message.name);
        policyPassed = true;
        if (isSideEffect) {
          sideEffectCallCount += 1;
          sideEffectStarted = true;
        }
        const tool = input.catalog.get(message.name);
        if (!tool) throw new Error("Tool left the current catalog.");
        const result = await tool.execute(message.callId, validation.arguments as never, abortController.signal);
        failed = resultFailed(result);
        const errorCode = resultErrorCode(result);
        const sideEffectOutcome = resultSideEffectOutcome(result);
        if (isSideEffect && failed) {
          if (sideEffectOutcome === "not_started") classifiedNoSideEffectFailure = true;
          else uncertainSideEffect = true;
        }
        ledger.status = failed ? "failed" : "completed";
        ledger.error_code = failed ? errorCode : undefined;
        ledger.side_effect_outcome = failed ? sideEffectOutcome : undefined;
        ledger.evidence_receipt = evidenceReceipt(result);
        const payload = boundedNestedResult(result, input.limits.maxOutputBytes);
        response = {
          ok: !failed,
          payloadJson: failed ? undefined : JSON.stringify(payload),
          error: failed ? errorCode ? `Nested tool returned ${errorCode}.` : "Nested tool returned a failed result." : undefined,
        };
      } catch {
        failed = true;
        if (isSideEffect && policyPassed) uncertainSideEffect = true;
        ledger.status = policyPassed ? "failed" : "blocked";
        if (!policyPassed) brokerLimitReason ??= "policy";
        response = { ok: false, error: policyPassed ? "Nested tool execution failed." : "Nested tool policy blocked the call." };
      } finally {
        if (policyPassed) {
          try {
            await input.options.afterToolCall?.(message.name, failed);
          } catch {
            failed = true;
            if (isSideEffect) uncertainSideEffect = true;
            ledger.status = "failed";
            response = { ok: false, error: "Nested tool result finalization failed." };
          }
        }
        if (isSideEffect) {
          writeQueued = false;
          releaseWriteGate?.();
          releaseWriteGate = undefined;
        }
      }
      respond(response);
    };
    const pending = execute();
    if (!isSideEffect) {
      activeReads.add(pending);
      pending.finally(() => activeReads.delete(pending)).catch(() => undefined);
    }
    await pending;
  };

  const exit = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    let resolved = false;
    const resolveExit = (code: number | null, signal: NodeJS.Signals | null) => {
      if (resolved) return;
      resolved = true;
      resolve({ code, signal });
    };
    child.once("error", () => {
      spawnFailed = true;
      terminate("child_exit");
    });
    child.on("message", (message: SandboxToParentMessage) => {
      if (!message || message.requestId !== input.requestId) {
        terminate("protocol");
        return;
      }
      if (message.type === "tool_call") {
        if (finalMessage) {
          terminate("protocol");
          return;
        }
        const pending = handleToolCall(message);
        inFlightCalls.add(pending);
        pending.finally(() => inFlightCalls.delete(pending)).catch(() => undefined);
        return;
      }
      if (message.type === "result") {
        if (finalMessage) {
          terminate("protocol");
          return;
        }
        finalHadPendingCalls = inFlightCalls.size > 0;
        finalHadPendingSideEffect = nestedCalls.some((entry) => entry.side_effect && entry.status === "started");
        finalMessage = message;
      }
    });
    child.once("exit", resolveExit);
    child.once("close", resolveExit);
  });

  const executeMessage: SandboxExecuteMessage = {
    type: "execute",
    requestId: input.requestId,
    script: input.program,
    toolNames: [...input.allowed].sort(),
    limits: {
      memoryLimitBytes: input.limits.memoryLimitBytes,
      maxOutputBytes: input.limits.maxOutputBytes,
      timeoutMs: input.limits.timeoutMs,
    },
  };
  if (input.signal?.aborted) onAbort();
  if (child.connected) {
    child.send(executeMessage, (error) => {
      if (error) terminate("child_exit");
    });
  } else {
    terminate("child_exit");
  }

  const exitState = await exit;
  clearTimeout(timeout);
  input.signal?.removeEventListener("abort", onAbort);
  abortController.abort();
  releaseWriteGate?.();

  const childExitClass: SandboxExecution["childExitClass"] = spawnFailed
    ? "spawn_error"
    : exitState.signal
      ? "signal"
      : exitState.code === 0
        ? "clean"
        : "error";
  const base = {
    childExitClass,
    toolCallCount,
    sideEffectCallCount: Math.min(sideEffectCallCount, input.limits.maxSideEffectCalls),
    retryAllowed: !uncertainSideEffect && (!sideEffectStarted || classifiedNoSideEffectFailure),
    nestedCalls: nestedCalls.map((entry) => ({ ...entry })),
  };
  if (finalHadPendingSideEffect || (sideEffectStarted && finalHadPendingCalls)) {
    return {
      ...base,
      outcome: "outcome_unknown",
      terminationReason: "protocol",
      outputTruncated: false,
    };
  }
  if (finalHadPendingCalls) {
    return {
      ...base,
      outcome: "terminated",
      terminationReason: "protocol",
      outputTruncated: false,
    };
  }
  if (forcedReason || !finalMessage) {
    const reason = forcedReason ?? "child_exit";
    return {
      ...base,
      outcome: sideEffectStarted && !classifiedNoSideEffectFailure ? "outcome_unknown" : reason === "deadline" ? "timed_out" : "terminated",
      terminationReason: reason,
      outputTruncated: false,
    };
  }
  if (!finalMessage.ok) {
    const reason = brokerLimitReason ?? resultLimitClass(finalMessage.errorCode);
    return {
      ...base,
      outcome: sideEffectStarted && !classifiedNoSideEffectFailure && reason !== "tool_limit" && reason !== "side_effect_limit" && reason !== "policy"
        ? "outcome_unknown"
        : reason === "deadline"
          ? "timed_out"
          : reason === "tool_limit" || reason === "side_effect_limit"
            ? "blocked"
            : "failed",
      terminationReason: reason,
      outputTruncated: reason === "output_limit",
    };
  }
  if (uncertainSideEffect) {
    return {
      ...base,
      outcome: "outcome_unknown",
      terminationReason: "guest_error",
      outputTruncated: false,
    };
  }
  if (brokerLimitReason) {
    return {
      ...base,
      outcome: "blocked",
      terminationReason: brokerLimitReason,
      outputTruncated: false,
    };
  }
  if (classifiedNoSideEffectFailure) {
    return {
      ...base,
      outcome: "failed",
      terminationReason: "guest_error",
      outputTruncated: false,
    };
  }
  try {
    const parsed = JSON.parse(finalMessage.resultJson ?? "{}");
    return {
      ...base,
      outcome: "completed",
      output: objectValue(parsed)?.value,
      terminationReason: "none",
      outputTruncated: false,
    };
  } catch {
    return {
      ...base,
      outcome: sideEffectStarted && !classifiedNoSideEffectFailure ? "outcome_unknown" : "terminated",
      terminationReason: "protocol",
      outputTruncated: false,
    };
  }
}

function spawnWorker(): ChildProcess {
  const javascriptPath = fileURLToPath(new URL("./worker.js", import.meta.url));
  const typescriptPath = fileURLToPath(new URL("./worker.ts", import.meta.url));
  const sourceRuntime = !existsSync(javascriptPath) && existsSync(typescriptPath);
  return fork(sourceRuntime ? typescriptPath : javascriptPath, [], {
    cwd: process.cwd(),
    env: { NODE_NO_WARNINGS: "1" },
    execArgv: sourceRuntime ? ["--import", "tsx"] : [],
    stdio: ["ignore", "ignore", "ignore", "ipc"],
    serialization: "json",
  });
}

function resultFailed(result: AgentToolResult<unknown>): boolean {
  const details = objectValue(result.details);
  if (hasUsablePartialToolEvidence(details)) return false;
  return Boolean(details?.error || details?.ok === false || details?.success === false);
}

function resultErrorCode(result: AgentToolResult<unknown>): string | undefined {
  const error = objectValue(result.details)?.error;
  return typeof error === "string" && /^[a-z][a-z0-9_]{0,119}$/.test(error) ? error : undefined;
}

function resultSideEffectOutcome(result: AgentToolResult<unknown>): "not_started" | undefined {
  return objectValue(result.details)?.side_effect_outcome === "not_started" ? "not_started" : undefined;
}

function evidenceReceipt(result: AgentToolResult<unknown>): string | undefined {
  const receipt = objectValue(result.details)?.evidence_receipt;
  return typeof receipt === "string" && receipt.length <= 240 ? receipt : undefined;
}

function boundedNestedResult(result: AgentToolResult<unknown>, maxOutputBytes: number): unknown {
  const details = result.details ?? result.content;
  return boundedToolDetails(details, Math.min(maxOutputBytes, 20_000));
}

function boundedToolName(name: unknown): string {
  return typeof name === "string" ? name.replace(/[^a-zA-Z0-9_.:-]/g, "").slice(0, 120) : "unknown";
}

function boundedRequestId(toolCallId: string): string {
  const suffix = toolCallId.replace(/[^a-zA-Z0-9_-]/g, "").slice(-48);
  return `${suffix || "code"}-${randomBytes(8).toString("hex")}`;
}

function resultLimitClass(errorCode: string | undefined): LimitClass {
  if (errorCode === "timeout") return "deadline";
  if (errorCode === "memory_limit") return "memory_limit";
  if (errorCode === "output_limit") return "output_limit";
  if (errorCode === "tool_limit") return "tool_limit";
  if (errorCode === "side_effect_limit") return "side_effect_limit";
  if (errorCode === "unawaited_tool_call") return "protocol";
  return "guest_error";
}

function executionToolResult(execution: SandboxExecution, maxOutputBytes: number): AgentToolResult<unknown> {
  const details = boundedToolDetails({
    outcome: execution.outcome,
    output: execution.output,
    tool_call_count: execution.toolCallCount,
    side_effect_call_count: execution.sideEffectCallCount,
    termination_reason: execution.terminationReason,
    child_exit_class: execution.childExitClass,
    output_truncated: execution.outputTruncated,
    nested_calls: execution.nestedCalls,
    verification_required: execution.outcome === "outcome_unknown",
    retry_allowed: execution.retryAllowed,
    message: outcomeMessage(execution),
  }, Math.min(maxOutputBytes, 20_000));
  const result = toolResult(details);
  return execution.outcome === "outcome_unknown" ? { ...result, terminate: true } : result;
}

function outcomeMessage(execution: SandboxExecution): string {
  if (execution.outcome === "completed") return "Code Mode completed. Use only nested source receipts as evidence.";
  if (execution.outcome === "outcome_unknown") return "A side effect may have completed after the host accepted it. Do not retry it. Verify the exact target with an independent registered read before reporting completion or attempting another action.";
  if (execution.outcome === "failed" && execution.retryAllowed && execution.sideEffectCallCount > 0) return "The host refused the side effect before it started. Read nested_calls.error_code, refresh the target state, and use a new execution if another attempt is needed.";
  if (execution.sideEffectCallCount > 0) return "Code Mode stopped after one side effect completed. Do not retry the program. Use the nested-call ledger and independently verify the exact target before another action.";
  if (execution.outcome === "timed_out") return "Code Mode reached its deadline without starting a side effect.";
  if (execution.outcome === "blocked") return "Code Mode blocked a call at the current catalog, plan, schema, or execution limit.";
  return "Code Mode did not complete. No source evidence was created by the outer executor.";
}

function annotateCodeSpan(span: Parameters<typeof annotateSpan>[0], execution: SandboxExecution, durationMs: number): void {
  annotateSpan(span, {
    "assistant.code.outcome": execution.outcome,
    "assistant.code.termination_reason": execution.terminationReason,
    "assistant.code.child_exit_class": execution.childExitClass,
    "assistant.code.tool_call_count": execution.toolCallCount,
    "assistant.code.side_effect_call_count": execution.sideEffectCallCount,
    "assistant.code.duration_ms": durationMs,
    "assistant.code.limit_class": execution.terminationReason,
    "assistant.code.output_truncated": execution.outputTruncated,
  });
}

function emitCodeExecutionEvent(execution: SandboxExecution): void {
  const attributes = {
    component: "security-assistant",
    operation: "execute",
    "assistant.code.outcome": execution.outcome,
    "assistant.code.termination_reason": execution.terminationReason,
    "assistant.code.child_exit_class": execution.childExitClass,
    "assistant.code.tool_call_count": execution.toolCallCount,
    "assistant.code.side_effect_call_count": execution.sideEffectCallCount,
    "assistant.code.limit_class": execution.terminationReason,
    "assistant.code.output_truncated": execution.outputTruncated,
  };
  if (execution.outcome === "outcome_unknown") telemetryEvent("assistant.code.outcome_unknown", attributes);
  else if (execution.outcome === "timed_out" || execution.outcome === "terminated") telemetryEvent("assistant.code.terminated", attributes);
  else if (execution.outcome === "blocked") telemetryEvent("assistant.code.blocked", attributes);
}
