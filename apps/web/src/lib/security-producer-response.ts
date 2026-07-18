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
) =>
  producers.find((producer) =>
    producer.sourceIds.includes(compact(finding.source_id)) ||
    producer.runtimeIds.includes(compact(finding.runtime_id)) ||
    finding.external_refs?.some((reference) => compact(reference.system) === producer.id),
  );

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
  producers: SecurityProducer[],
) => {
  const actions = new Map<string, SecurityProducerResponseAction>();
  producers.forEach((producer) => {
    producer.responseActions.forEach((action) => {
      if (!actions.has(action.id)) actions.set(action.id, action);
    });
  });
  return candidates.map((candidate) => responseActionHint(candidate, actions.get(candidate))).join(", ");
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
