import { createHash } from "node:crypto";
import { assessCompatibility } from "../operations/compatibility.js";
import { MAX_AGENT_FLEET_MEMBERS } from "./contracts.js";
import type {
  AgentFleetMemberV1,
  AgentFleetMessageV1,
  AgentFleetPeerCandidate,
  AgentFleetPeerCompatibility,
  AgentFleetPeerRanking,
  DistributedWorkPacketV1,
} from "./contracts.js";
import {
  AgentFleetContractError,
  validateAgentFleetMember,
  validateAgentFleetMessageForPacket,
  validateAgentFleetSender,
} from "./validation.js";

export interface AgentFleetPeerSelectionInput {
  candidates: readonly AgentFleetMemberV1[];
  excluded_member_ids?: readonly string[];
  message: AgentFleetMessageV1;
  observed_at: string;
  packet: DistributedWorkPacketV1;
  sender: AgentFleetMemberV1;
}

/**
 * Returns one deterministic order over compatible ready and degraded peers.
 * Capacity is deliberately excluded; callers reserve it atomically through
 * DurableCapacityPort after this pure policy step.
 */
export function rankCompatibleAgentFleetPeers(
  input: AgentFleetPeerSelectionInput,
): AgentFleetPeerRanking {
  validateAgentFleetMessageForPacket(input.message, input.packet);
  validateAgentFleetSender(input.message, input.sender, input.observed_at);
  const observedAt = Date.parse(input.observed_at);
  const excluded = new Set(input.excluded_member_ids ?? []);
  const seen = new Set<string>();
  const compatible: AgentFleetPeerCandidate[] = [];
  const rejected: AgentFleetPeerRanking["rejected"] = [];

  if (input.candidates.length > MAX_AGENT_FLEET_MEMBERS) {
    throw new AgentFleetContractError("fleet candidate set exceeds its bound");
  }
  for (const member of input.candidates) {
    validateAgentFleetMember(member);
    if (seen.has(member.member_id)) {
      throw new AgentFleetContractError("fleet candidate set has duplicate members");
    }
    seen.add(member.member_id);

    const lifecycleReasons: string[] = [];
    if (member.member_id === input.sender.member_id) {
      lifecycleReasons.push("sender_is_not_a_peer");
    }
    if (excluded.has(member.member_id)) {
      lifecycleReasons.push("member_excluded");
    }
    if (member.state !== "ready" && member.state !== "degraded") {
      lifecycleReasons.push(`member_${member.state}`);
    }
    if (Date.parse(member.valid_until) <= observedAt) {
      lifecycleReasons.push("member_presence_expired");
    }
    if (lifecycleReasons.length > 0) {
      rejected.push({ member_id: member.member_id, reasons: lifecycleReasons });
      continue;
    }

    const compatibility = assessPeerCompatibility(
      input.sender,
      member,
      input.packet,
    );
    if (
      compatibility.decision === "blocked" ||
      compatibility.decision === "incompatible"
    ) {
      rejected.push({
        member_id: member.member_id,
        reasons: [...compatibility.reasons],
      });
      continue;
    }
    compatible.push({
      compatibility,
      member: structuredClone(member),
      rank: peerRank(input.message.message_id, member.member_id),
    });
  }

  compatible.sort(compareCandidates);
  rejected.sort((left, right) => left.member_id.localeCompare(right.member_id));
  return { compatible, rejected };
}

export function selectCompatibleAgentFleetPeer(
  input: AgentFleetPeerSelectionInput,
): AgentFleetPeerCandidate | undefined {
  return rankCompatibleAgentFleetPeers(input).compatible[0];
}

function assessPeerCompatibility(
  sender: AgentFleetMemberV1,
  member: AgentFleetMemberV1,
  packet: DistributedWorkPacketV1,
): AgentFleetPeerCompatibility {
  if (
    !sender.capability_manifest.contract_versions.includes(
      sender.protocol_version,
    ) ||
    !member.capability_manifest.contract_versions.includes(
      sender.protocol_version,
    )
  ) {
    return {
      decision: "incompatible",
      member_id: member.member_id,
      reasons: ["fleet_protocol_version_not_shared"],
    };
  }

  const assessed = assessCompatibility({
    companion_manifest: sender.capability_manifest,
    companion_schema: sender.schema_compatibility,
    core_manifest: member.capability_manifest,
    core_schema: member.schema_compatibility,
  });
  const reasons = assessed.reasons.map(normalizeCompatibilityReason);
  const requiredMissing = packet.required_capabilities
    .filter((requirement) => requirement.level === "required")
    .filter(
      (requirement) =>
        !member.capability_manifest.capabilities.some(
          (offered) =>
            offered.capability_id === requirement.capability_id &&
            offered.version === requirement.version,
        ),
    )
    .map(
      (requirement) =>
        `peer_missing_${requirement.capability_id}@${requirement.version}`,
    );
  if (requiredMissing.length > 0) {
    return {
      decision: "blocked",
      member_id: member.member_id,
      negotiated_write_version: assessed.negotiated_write_version,
      reasons: [...reasons, ...requiredMissing],
    };
  }

  const optionalMissing = packet.required_capabilities
    .filter((requirement) => requirement.level === "optional")
    .filter(
      (requirement) =>
        !member.capability_manifest.capabilities.some(
          (offered) =>
            offered.capability_id === requirement.capability_id &&
            offered.version === requirement.version,
        ),
    )
    .map(
      (requirement) =>
        `peer_optional_${requirement.capability_id}@${requirement.version}`,
    );
  const decision =
    assessed.decision === "supported" && optionalMissing.length > 0
      ? "degraded"
      : assessed.decision;
  return {
    decision,
    member_id: member.member_id,
    negotiated_write_version: assessed.negotiated_write_version,
    reasons: [...reasons, ...optionalMissing],
  };
}

function normalizeCompatibilityReason(reason: string): string {
  return reason
    .replace(/^companion_/, "requester_")
    .replace(/^core_/, "peer_")
    .replace(/^manifest_/, "fleet_manifest_");
}

function peerRank(messageId: string, memberId: string): string {
  return createHash("sha256")
    .update(`${messageId}\u0000${memberId}`)
    .digest("hex");
}

function compareCandidates(
  left: AgentFleetPeerCandidate,
  right: AgentFleetPeerCandidate,
): number {
  if (left.member.state !== right.member.state) {
    return left.member.state === "ready" ? -1 : 1;
  }
  const byRank = right.rank.localeCompare(left.rank);
  return byRank !== 0
    ? byRank
    : left.member.member_id.localeCompare(right.member.member_id);
}
