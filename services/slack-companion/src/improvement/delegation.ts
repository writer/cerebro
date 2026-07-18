import { createHash } from "node:crypto";
import { KMSClient, SignCommand } from "@aws-sdk/client-kms";
import { z } from "zod";
import type { ImprovementCandidateSource } from "./candidate-author.js";
import { stableJson } from "./artifacts.js";
import {
  improvementDelegationManifestSchema,
  signedImprovementDelegationSchema,
  type ImprovementAuthorRequest,
  type ImprovementDelegationManifest,
  type ImprovementDelegationRolloutMode,
  type ImprovementRun,
  type SignedImprovementDelegation,
} from "./types.js";

interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

const resolvedRefSchema = z.object({
  ok: z.literal(true),
  repo: z.string().min(3).max(200),
  resolved_ref: z.string().regex(/^[a-f0-9]{40}$/i),
}).passthrough();

export interface ImprovementDelegationIssueInput {
  run: ImprovementRun;
  request: ImprovementAuthorRequest;
  jobKind?: "author_candidate" | "open_candidate_pr";
}

export interface ImprovementDelegationIssuer {
  issue(input: ImprovementDelegationIssueInput): Promise<SignedImprovementDelegation>;
}

export interface ImprovementDelegationIssuerConfig {
  keyId: string;
  defaultRepo: string;
  rolloutMode: ImprovementDelegationRolloutMode;
  canaryBasisPoints: number;
  ttlSeconds: number;
  policyVersion: string;
  toolsetVersion: string;
  budgets: ImprovementDelegationManifest["budgets"];
}

export class KmsImprovementDelegationIssuer implements ImprovementDelegationIssuer {
  private readonly kms: CommandSender;
  private readonly now: () => Date;

  constructor(
    private readonly config: ImprovementDelegationIssuerConfig,
    private readonly source: ImprovementCandidateSource,
    options: { kms?: CommandSender; now?: () => Date } = {},
  ) {
    this.kms = options.kms ?? new KMSClient({});
    this.now = options.now ?? (() => new Date());
  }

  async issue(input: ImprovementDelegationIssueInput): Promise<SignedImprovementDelegation> {
    const repo = input.request.repo ?? this.config.defaultRepo;
    const baseSha = await this.resolve(repo, input.request.baseRef);
    const sourceRef = input.run.refinementBaseVersion ?? input.request.baseRef;
    const sourceSha = sourceRef === input.request.baseRef ? baseSha : await this.resolve(repo, sourceRef);
    const issuedAt = this.now();
    const cohortKey = `${input.run.id}:${input.request.generation}:${repo}:${baseSha}`;
    const cohortBucket = deterministicCohortBucket(cohortKey);
    const manifestId = `delegation-${createHash("sha256")
      .update(`${cohortKey}:${sourceSha}:${issuedAt.toISOString()}`)
      .digest("hex")
      .slice(0, 32)}`;
    const manifest = improvementDelegationManifestSchema.parse({
      schemaVersion: 1,
      manifestId,
      issuer: "cerebro-improvement-control-plane",
      runId: input.run.id,
      generation: input.request.generation,
      jobKind: input.jobKind ?? "author_candidate",
      inputSignalShas: input.request.inputSignalShas,
      repo,
      baseRef: input.request.baseRef,
      baseSha,
      sourceSha,
      authority: ["repository:read", "pull_request:draft"],
      budgets: this.config.budgets,
      policyVersion: this.config.policyVersion,
      toolsetVersion: this.config.toolsetVersion,
      rollout: {
        mode: this.config.rolloutMode,
        cohortBucket,
        canaryBasisPoints: this.config.canaryBasisPoints,
      },
      issuedAt: issuedAt.toISOString(),
      notBefore: new Date(issuedAt.getTime() - 30_000).toISOString(),
      expiresAt: new Date(issuedAt.getTime() + this.config.ttlSeconds * 1_000).toISOString(),
    });
    const result = await this.kms.send(new SignCommand({
      KeyId: this.config.keyId,
      Message: Buffer.from(stableJson(manifest), "utf8"),
      MessageType: "RAW",
      SigningAlgorithm: "ECDSA_SHA_256",
    })) as { Signature?: Uint8Array };
    if (!result.Signature?.byteLength) throw new Error("Delegation signer returned no signature.");
    return signedImprovementDelegationSchema.parse({
      manifest,
      signature: Buffer.from(result.Signature).toString("base64"),
    });
  }

  private async resolve(repo: string, ref: string): Promise<string> {
    const result = resolvedRefSchema.safeParse(await this.source.sourceList({ repo, ref, maxEntries: 1 }));
    if (!result.success || result.data.repo !== repo) {
      throw new Error(`Delegation issuer could not resolve ${repo}@${ref} to an immutable commit.`);
    }
    return result.data.resolved_ref.toLowerCase();
  }
}

export function deterministicCohortBucket(value: string): number {
  return Number.parseInt(createHash("sha256").update(value).digest("hex").slice(0, 8), 16) % 10_000;
}

export function delegationExecutionDecision(manifest: ImprovementDelegationManifest): "execute" | "shadow" {
  if (manifest.rollout.mode === "active") return "execute";
  if (manifest.rollout.mode === "canary"
    && manifest.rollout.cohortBucket < manifest.rollout.canaryBasisPoints) return "execute";
  return "shadow";
}

export function assertDelegationFresh(manifest: ImprovementDelegationManifest, now: Date): void {
  const notBefore = Date.parse(manifest.notBefore);
  const expiresAt = Date.parse(manifest.expiresAt);
  if (!Number.isFinite(notBefore) || !Number.isFinite(expiresAt)
    || now.getTime() < notBefore || now.getTime() >= expiresAt) {
    throw new Error("Signed delegation is not active at the execution time.");
  }
}
