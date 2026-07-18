import { securityProducers, type SecurityProducer } from "./security-producers";

const actionsFor = (producers: SecurityProducer[]) => new Map(
  producers
    .filter((producer) => producer.id === "aperio")
    .flatMap((producer) => producer.responseActions)
    .map((action) => [action.id, action]),
);

export const aperioProposalActionForCandidate = (
  candidate: string,
  producers: SecurityProducer[] = securityProducers,
) => actionsFor(producers).get(candidate)?.runtimeAction || candidate;

export const aperioResponseCandidateHint = (
  candidates: string[],
  producers: SecurityProducer[] = securityProducers,
) => candidates.length === 0
  ? "Response proposal"
  : candidates.map((candidate) => aperioResponseCandidateHintForCandidate(candidate, producers)).join(", ");

export const aperioResponseCandidateHintForCandidate = (
  candidate: string,
  producers: SecurityProducer[] = securityProducers,
) => {
  const action = actionsFor(producers).get(candidate);
  if (!action) return candidate;
  const proposalAction = action.runtimeAction || candidate;
  const provider = action.providers.find((value) => value !== "ALL");
  const providerHint = provider ? ` and provider=${provider}` : "";
  const tool = action.mcpTool ? `call ${action.mcpTool}` : "use the configured response tool";
  return `${candidate} (${tool} with action=${proposalAction}${providerHint})`;
};
