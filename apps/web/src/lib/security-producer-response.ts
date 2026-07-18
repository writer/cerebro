import type { GRCFinding } from "@/lib/grc";
import {
  type SecurityProducer,
  type SecurityProducerResponseAction,
} from "@/lib/security-producers";

type FindingLike = Pick<GRCFinding, "attributes" | "external_refs" | "runtime_id" | "source_id">;

const compact = (value?: string) => value?.trim() ?? "";

const providerTokens = (finding: FindingLike) =>
  new Set(
    [
      finding.attributes?.provider,
      finding.attributes?.saasProvider,
      finding.attributes?.saas_provider,
    ]
      .map((value) => compact(value).toUpperCase())
      .filter(Boolean),
  );

export const securityProducerForFinding = (
  finding: FindingLike,
  producers: SecurityProducer[],
) => {
  const matches = producers.filter((producer) =>
    producer.sourceIds.includes(compact(finding.source_id)) ||
    producer.runtimeIds.includes(compact(finding.runtime_id)) ||
    finding.external_refs?.some((reference) => compact(reference.system) === producer.id),
  );
  return matches.length === 1 ? matches[0] : undefined;
};

export const securityProducerResponseActionCandidates = (
  finding: FindingLike,
  producers: SecurityProducer[],
) => {
  const producer = securityProducerForFinding(finding, producers);
  if (!producer) return [];
  const providers = providerTokens(finding);
  return producer.responseActions
    .filter((action) =>
      action.providers.includes("ALL") ||
      action.providers.some((provider) => providers.has(provider.toUpperCase())),
    )
    .map((action) => action.id);
};

export const securityProducerResponseCandidateHint = (
  candidates: string[],
  producer: SecurityProducer,
) => {
  const actions = new Map(
    producer.responseActions.map((action) => [action.id, action]),
  );
  return candidates.flatMap((candidate) => {
    const action = actions.get(candidate);
    return action ? [responseActionHint(candidate, action)] : [];
  }).join(", ");
};

export const resolveSecurityProducerGuidance = (
  producerID: string,
  candidates: string[],
  producers: SecurityProducer[],
) => {
  const producerMatches = producers.filter((producer) => producer.id === producerID);
  if (producerMatches.length !== 1) return null;
  const producer = producerMatches[0];
  const normalizedCandidates = candidates.map(compact);
  if (normalizedCandidates.some((candidate) => !candidate)) return null;
  const actionIDs = new Set(producer.responseActions.map((action) => action.id));
  if (normalizedCandidates.some((candidate) => !actionIDs.has(candidate))) return null;
  return {
    producer,
    candidates: [...new Set(normalizedCandidates)],
  };
};

export const securityProducerContextForFinding = (
  finding: FindingLike,
  producers: SecurityProducer[],
) => ({
  security_producer_id: securityProducerForFinding(finding, producers)?.id,
  response_action_candidates: securityProducerResponseActionCandidates(finding, producers),
});

const responseActionHint = (candidate: string, action?: SecurityProducerResponseAction) => {
  if (!action) return candidate;
  const provider = action.providers.find((value) => value !== "ALL");
  const tool = action.mcpTool ? ` via ${action.mcpTool}` : "";
  const providerHint = provider ? ` for provider=${provider}` : "";
  const approval = action.requiresApproval ? "; approval required" : "";
  const mode = action.dryRun ? "; dry run" : "";
  return `${candidate}${tool}${providerHint}${approval}${mode}`;
};
