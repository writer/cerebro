import type { WorkLeaseV1 } from "@writer/cerebro-sdk";
import type {
  DistributedWorkDelegationSignatureV1,
} from "./delegation-contracts.js";

export interface DistributedWorkDelegationSigningInput {
  canonical_manifest: string;
  issuer_ref: string;
  key_ref: string;
  manifest_digest: string;
}

export interface DistributedWorkDelegationSigningResult {
  signature_suite: string;
  signature_value: string;
}

export interface DistributedWorkDelegationSigningPort {
  sign(
    input: DistributedWorkDelegationSigningInput,
  ): Promise<DistributedWorkDelegationSigningResult>;
}

export interface DistributedWorkDelegationVerificationInput
  extends DistributedWorkDelegationSigningInput {
  signature: DistributedWorkDelegationSignatureV1;
}

export interface DistributedWorkDelegationVerificationPort {
  verify(input: DistributedWorkDelegationVerificationInput): Promise<boolean>;
}

export interface DistributedWorkDelegationRevocationInput {
  delegation_id: string;
  observed_at: string;
  revocation_ref: string;
}

export interface DistributedWorkDelegationRevocationPort {
  isRevoked(input: DistributedWorkDelegationRevocationInput): Promise<boolean>;
}

/** Supplies authorization time from a trusted process boundary. */
export interface DistributedWorkDelegationClockPort {
  now(): string;
}

export interface DistributedWorkDelegationCurrentLeaseInput {
  delegation_id: string;
  observed_at: string;
  packet_id: string;
  run_id: string;
  tenant_id: string;
}

/** Reads the authoritative lease that currently owns the delegated run. */
export interface DistributedWorkDelegationCurrentLeasePort {
  getCurrentLease(
    input: DistributedWorkDelegationCurrentLeaseInput,
  ): Promise<WorkLeaseV1 | undefined>;
}
