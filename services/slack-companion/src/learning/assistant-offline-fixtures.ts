import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { createResearchTools } from "../agent/tools/research-tools.js";
import { instrumentTools, toolResult } from "../agent/tools/tool-result.js";
import type { SecurityToolFactory } from "../agent/tools/types.js";
import type { AssistantHardCorpusCase } from "./assistant-hillclimb.js";

export interface OfflineFixtureSource {
  toolName: string;
  source: string;
  receipt: string;
  status: "completed" | "failed" | "partial";
  subjects: string[];
}

export interface OfflineFixtureCall {
  toolName: string;
  source: string;
  status: OfflineFixtureSource["status"];
}

export interface OfflineFixtureTrace {
  sources: OfflineFixtureSource[];
  calls: OfflineFixtureCall[];
}

export function createOfflineFixtureTrace(): OfflineFixtureTrace {
  return { sources: [], calls: [] };
}

export function createOfflineFixtureToolFactory(
  item: AssistantHardCorpusCase,
  trace: OfflineFixtureTrace,
): SecurityToolFactory {
  trace.sources = item.evidence.map((packet, index) => ({
    toolName: fixtureToolName(packet.source, index),
    source: packet.source,
    receipt: packet.receipt,
    status: packet.status,
    subjects: [...packet.subjects],
  }));
  return (deps) => {
    const fixtures = item.evidence.map((packet, index) => fixtureTool(packet, index, trace));
    const tools = [...createResearchTools(deps), ...fixtures];
    deps.researchState?.setAvailableTools(tools.map((tool) => tool.name));
    return instrumentTools(tools, deps.researchState);
  };
}

function fixtureTool(
  packet: AssistantHardCorpusCase["evidence"][number],
  index: number,
  trace: OfflineFixtureTrace,
): AgentTool {
  const name = fixtureToolName(packet.source, index);
  return {
    name,
    label: `${packet.source} evidence`,
    description: `Read the ${packet.source} result for this offline evaluation case. The result is bounded to the supplied source scope and may report a failed or partial check.`,
    parameters: Type.Object({}),
    execute: async () => {
      trace.calls.push({ toolName: name, source: packet.source, status: packet.status });
      const records = fixtureRecords(packet);
      if (packet.status === "completed") {
        return toolResult({
          success: true,
          status: packet.status,
          source: packet.source,
          source_scope: "offline evaluation fixture",
          facts: packet.facts,
          records,
        });
      }
      return toolResult({
        success: false,
        status: packet.status,
        source: packet.source,
        source_scope: "offline evaluation fixture",
        facts: packet.facts,
        records,
        error: packet.status === "partial" ? "source returned partial coverage" : "source check failed",
      });
    },
  };
}

function fixtureRecords(packet: AssistantHardCorpusCase["evidence"][number]): Array<Record<string, unknown>> {
  const subjects = packet.subjects.length > 0 ? packet.subjects : [`source:${slug(packet.source)}`];
  const url = packet.facts.flatMap((fact) => fact.match(/https:\/\/[^\s]+/g) ?? [])[0];
  return subjects.map((subject) => ({
    id: subject,
    type: subject.split(":", 1)[0] || "source",
    title: subject,
    source: packet.source,
    facts: packet.facts,
    ...(url ? { url: url.replace(/[.,;)]$/, "") } : {}),
  }));
}

function fixtureToolName(source: string, index: number): string {
  return `offline_source_${String(index + 1).padStart(2, "0")}_${slug(source)}`.slice(0, 96);
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 48) || "evidence";
}
