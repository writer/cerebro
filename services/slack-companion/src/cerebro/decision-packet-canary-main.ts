import { pathToFileURL } from "node:url";
import { loadConfig } from "../config/index.js";
import { CerebroClient } from "./client.js";
import type { DecisionPacket, DecisionPacketBuildRequest, JsonRecord } from "./types.js";

const CANARY_SOURCE = "deployment-canary";
const PACKET_ID_PATTERN = /^dpr_[a-f0-9]{32}$/;

type DecisionPacketCanaryClient = Pick<
  CerebroClient,
  "buildDecisionPacket" | "getDecisionPacket" | "listSourceRuntimes"
>;

export interface DecisionPacketCanaryReceipt {
  runtimeCount: number;
  packetId: string;
  recheckPacketId: string;
  decisionState: string;
}

export async function verifyDecisionPacketLifecycle(
  client: DecisionPacketCanaryClient,
  tenantId: string,
): Promise<DecisionPacketCanaryReceipt> {
  const runtimePayload = await client.listSourceRuntimes({ limit: 1 });
  const runtimeCount = runtimeRows(runtimePayload).length;
  if (runtimeCount === 0) throw new Error("Cerebro returned no runtimes for the configured tenant");

  const request: DecisionPacketBuildRequest = {
    workflow: "deployment_canary",
    question: "Can this tenant build and reopen a current decision receipt?",
    required_sources: [CANARY_SOURCE],
  };
  const packet = await client.buildDecisionPacket(request);
  assertPacket(packet, tenantId, request.required_sources ?? []);

  const reopened = await client.getDecisionPacket(packet.id);
  assertPacket(reopened, tenantId, request.required_sources ?? []);
  if (reopened.id !== packet.id) throw new Error("Cerebro reopened a different decision receipt");
  if (reopened.provenance.evidence_digest !== packet.provenance.evidence_digest
    || reopened.provenance.coverage_digest !== packet.provenance.coverage_digest) {
    throw new Error("Cerebro changed an immutable decision receipt digest");
  }

  const recheck = await client.buildDecisionPacket(recheckRequest(reopened));
  assertPacket(recheck, tenantId, request.required_sources ?? []);
  if (recheck.id === reopened.id) throw new Error("Cerebro recheck did not create a new decision receipt");

  return {
    runtimeCount,
    packetId: reopened.id,
    recheckPacketId: recheck.id,
    decisionState: recheck.decision.state,
  };
}

function recheckRequest(packet: DecisionPacket): DecisionPacketBuildRequest {
  return {
    workflow: packet.workflow.id,
    question: packet.workflow.question,
    scope_urn: packet.scope.urn,
    finding_ids: packet.inputs.finding_ids,
    claim_ids: packet.inputs.claim_ids,
    evidence_urns: packet.inputs.evidence_urns,
    audit_packet_ids: packet.inputs.audit_packet_ids,
    required_sources: packet.inputs.required_sources,
    requested_action: packet.inputs.requested_action,
  };
}

function assertPacket(packet: DecisionPacket, tenantId: string, requiredSources: string[]): void {
  if (!PACKET_ID_PATTERN.test(packet.id)) throw new Error("Cerebro returned an invalid decision receipt id");
  if (packet.scope.tenant_id !== tenantId || !packet.scope.actor_id) {
    throw new Error("Cerebro did not bind the decision receipt to server-owned identity");
  }
  if (!packet.decision.state || !packet.confidence.level) {
    throw new Error("Cerebro did not derive the decision receipt conclusion");
  }
  if (!packet.provenance.evidence_digest || !packet.provenance.coverage_digest) {
    throw new Error("Cerebro returned a decision receipt without immutable digests");
  }
  if (!sameStrings(packet.inputs.required_sources, requiredSources)) {
    throw new Error("Cerebro did not retain the decision receipt resolver inputs");
  }
  if (packet.actions.some((action) => "executed" in action)) {
    throw new Error("Cerebro decision receipt included action execution state");
  }
}

function sameStrings(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function runtimeRows(payload: JsonRecord): unknown[] {
  for (const key of ["runtimes", "items", "source_runtimes"]) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  throw new Error("Cerebro response did not include a runtime list");
}

async function main(): Promise<void> {
  try {
    const config = loadConfig();
    const receipt = await verifyDecisionPacketLifecycle(new CerebroClient(config), config.cerebro.tenantId);
    process.stdout.write(
      `Cerebro target accepted the configured credential: tenant=${config.cerebro.tenantId} runtimes_returned=${receipt.runtimeCount} decision_packet=${receipt.packetId} recheck_packet=${receipt.recheckPacketId} decision_state=${receipt.decisionState}\n`,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected decision packet canary failure";
    process.stderr.write(`Cerebro target check failed: ${message}\n`);
    process.exitCode = 1;
  }
}

const entrypoint = process.argv[1];
if (entrypoint && import.meta.url === pathToFileURL(entrypoint).href) await main();
