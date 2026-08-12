import { createHash } from "node:crypto";

import { AgentGymContractError } from "./contract-error.js";
import type { AgentGymJson } from "./fixture-case.js";

const MAXIMUM_DEPTH = 100;

/** Encodes portable agent-gym data with stable object-key ordering. */
export function canonicalAgentGymJson(value: AgentGymJson): string {
  return encode(value, 0);
}

/** Returns a content identity for portable agent-gym data. */
export function digestAgentGymJson(value: AgentGymJson): string {
  return `sha256:${createHash("sha256").update(canonicalAgentGymJson(value), "utf8").digest("hex")}`;
}

function encode(value: AgentGymJson, depth: number): string {
  if (depth > MAXIMUM_DEPTH) invalid();
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) invalid();
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (Object.keys(value).length !== value.length) invalid();
    return `[${value.map((item) => encode(item, depth + 1)).join(",")}]`;
  }
  if (typeof value !== "object") invalid();
  const prototype = Object.getPrototypeOf(value) as object | null;
  if (prototype !== Object.prototype && prototype !== null) invalid();
  const keys = Object.keys(value).sort();
  if (Reflect.ownKeys(value).length !== keys.length) invalid();
  return `{${keys.map((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) invalid();
    return `${JSON.stringify(key)}:${encode(descriptor.value as AgentGymJson, depth + 1)}`;
  }).join(",")}}`;
}

function invalid(): never {
  throw new AgentGymContractError("Agent gym canonical JSON is invalid.");
}
