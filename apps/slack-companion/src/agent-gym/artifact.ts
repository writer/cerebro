import { createHash } from "node:crypto";
import { AgentGymContractError } from "./index.js";

export interface AgentGymArtifactIdentityV1 {
  readonly byte_length: number;
  readonly content_digest: `sha256:${string}`;
  readonly media_type: "application/json" | "application/x-ndjson" | "text/plain";
  readonly schema_version: "agent-gym-artifact-identity/v1";
}

/** Computes a content address without selecting a storage provider. */
export function identifyAgentGymArtifact(
  bytes: Uint8Array,
  mediaType: AgentGymArtifactIdentityV1["media_type"],
): AgentGymArtifactIdentityV1 {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0
    || bytes.byteLength > 64 * 1024 * 1024
    || !["application/json", "application/x-ndjson", "text/plain"].includes(mediaType)) {
    throw new AgentGymContractError("Agent gym artifact is invalid.");
  }
  return Object.freeze({
    byte_length: bytes.byteLength,
    content_digest: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
    media_type: mediaType,
    schema_version: "agent-gym-artifact-identity/v1",
  });
}
