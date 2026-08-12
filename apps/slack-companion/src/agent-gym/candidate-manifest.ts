import { AgentGymContractError } from "./contract-error.js";

export interface AgentGymCandidateManifestV1 {
  readonly candidate_ref: string;
  readonly max_output_tokens: number;
  readonly model_id: string;
  readonly policy_digest: `sha256:${string}`;
  readonly prompt_digest: `sha256:${string}`;
  readonly provider: "aws_bedrock" | "recorded";
  readonly region?: string;
  readonly schema_version: "agent-gym-candidate-manifest/v1";
  readonly source_revision: string;
  readonly tool_catalog_digest: `sha256:${string}`;
  readonly tool_ids: readonly string[];
}

/** Binds an evaluated candidate to exact source, prompt, policy, tools, and model. */
export function validateAgentGymCandidateManifest(
  manifest: AgentGymCandidateManifestV1,
): AgentGymCandidateManifestV1 {
  if (manifest.schema_version !== "agent-gym-candidate-manifest/v1") invalid();
  reference(manifest.candidate_ref);
  bounded(manifest.model_id, 240);
  digest(manifest.policy_digest);
  digest(manifest.prompt_digest);
  digest(manifest.tool_catalog_digest);
  if (!/^[0-9a-f]{40}$/u.test(manifest.source_revision)) invalid();
  if (!Number.isSafeInteger(manifest.max_output_tokens)
    || manifest.max_output_tokens < 1 || manifest.max_output_tokens > 32_768) invalid();
  if (!["aws_bedrock", "recorded"].includes(manifest.provider)) invalid();
  if (manifest.provider === "aws_bedrock") {
    if (manifest.region === undefined || !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/u.test(manifest.region)) invalid();
  } else if (manifest.region !== undefined) invalid();
  if (!Array.isArray(manifest.tool_ids) || manifest.tool_ids.length > 128
    || new Set(manifest.tool_ids).size !== manifest.tool_ids.length) invalid();
  for (const toolId of manifest.tool_ids) bounded(toolId, 160);
  return Object.freeze({ ...manifest, tool_ids: Object.freeze([...manifest.tool_ids]) });
}

function bounded(value: string, maximum: number): void {
  if (typeof value !== "string" || !value.trim() || value.length > maximum
    || /[\u0000-\u001f\u007f]/u.test(value)) invalid();
}
function digest(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid();
}
function reference(value: string): void {
  bounded(value, 240);
  if (!value.includes("://")) invalid();
}
function invalid(): never {
  throw new AgentGymContractError("Agent gym candidate manifest is invalid.");
}
