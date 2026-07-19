import type { GRCFinding } from "@/lib/grc";
import {
  securityProducerForFinding,
  securityProducerResponseActionCandidates,
} from "@/lib/security-producer-response";
import type { SecurityProducer } from "@/lib/security-producers";

type FindingLike = Pick<GRCFinding, "attributes" | "external_refs" | "runtime_id" | "source_id">;

export const isAperioOwnedFinding = (
  finding: FindingLike,
  producers: SecurityProducer[],
) => securityProducerForFinding(finding, producers)?.id === "aperio";

export const aperioResponseOwner = (
  finding: FindingLike,
  producers: SecurityProducer[],
) => isAperioOwnedFinding(finding, producers) ? "aperio" : undefined;

export const aperioResponseActionCandidates = (
  finding: FindingLike,
  producers: SecurityProducer[],
) => isAperioOwnedFinding(finding, producers)
  ? securityProducerResponseActionCandidates(finding, producers)
  : [];
