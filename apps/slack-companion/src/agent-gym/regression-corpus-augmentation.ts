import { digestAgentGymJson } from "./canonical-json.js";
import { AgentGymContractError } from "./contract-error.js";
import { createAgentGymCorpusManifest } from "./corpus-manifest.js";
import { agentGymFixtureScenarioDigest, validateAgentGymFixtureCase, type AgentGymFixtureCaseV1 } from "./fixture-case.js";
import { validateAgentGymRegressionFixtureReceipt, type AgentGymRegressionFixtureReceiptV1 } from "./regression-fixture.js";

export interface AgentGymRegressionCorpusAugmentationV1 {
  readonly added_case_digest: string;
  readonly added_case_ref: string;
  readonly augmented_at: string;
  readonly augmentation_digest: string;
  readonly augmentation_ref: string;
  readonly fixture_receipt_digest: string;
  readonly next_case_count: number;
  readonly next_corpus_digest: string;
  readonly previous_case_count: number;
  readonly previous_corpus_digest: string;
  readonly schema_version: "agent-gym-regression-corpus-augmentation/v1";
}

/** Appends one admitted training regression while preserving the prior corpus identity. */
export function augmentAgentGymRegressionCorpus(
  previousFixturesValue: readonly AgentGymFixtureCaseV1[],
  receiptValue: AgentGymRegressionFixtureReceiptV1,
  input: Pick<AgentGymRegressionCorpusAugmentationV1, "augmentation_ref" | "augmented_at">,
): AgentGymRegressionCorpusAugmentationV1 {
  if (previousFixturesValue.length === 0 || previousFixturesValue.length >= 100_000) invalid();
  const previousFixtures = previousFixturesValue.map(validateAgentGymFixtureCase);
  const receipt = validateAgentGymRegressionFixtureReceipt(receiptValue);
  reference(input.augmentation_ref); timestamp(input.augmented_at);
  if (previousFixtures.some((fixture) => fixture.case_ref === receipt.fixture.case_ref
    || agentGymFixtureScenarioDigest(fixture) === agentGymFixtureScenarioDigest(receipt.fixture))) invalid();
  const previous = createAgentGymCorpusManifest(previousFixtures);
  const next = createAgentGymCorpusManifest([...previousFixtures, receipt.fixture]);
  const body = {
    added_case_digest: receipt.fixture_digest,
    added_case_ref: receipt.fixture.case_ref,
    augmented_at: input.augmented_at,
    augmentation_ref: input.augmentation_ref,
    fixture_receipt_digest: receipt.receipt_digest,
    next_case_count: next.case_count,
    next_corpus_digest: next.corpus_digest,
    previous_case_count: previous.case_count,
    previous_corpus_digest: previous.corpus_digest,
    schema_version: "agent-gym-regression-corpus-augmentation/v1" as const,
  };
  return Object.freeze({ ...body, augmentation_digest: digestAgentGymJson(body) });
}

export function validateAgentGymRegressionCorpusAugmentation(
  value: AgentGymRegressionCorpusAugmentationV1,
): AgentGymRegressionCorpusAugmentationV1 {
  if (value.schema_version !== "agent-gym-regression-corpus-augmentation/v1") invalid();
  reference(value.added_case_ref); reference(value.augmentation_ref); timestamp(value.augmented_at);
  for (const item of [value.added_case_digest, value.fixture_receipt_digest, value.next_corpus_digest,
    value.previous_corpus_digest, value.augmentation_digest]) digest(item);
  if (!Number.isSafeInteger(value.previous_case_count) || value.previous_case_count < 1
    || value.next_case_count !== value.previous_case_count + 1 || value.next_case_count > 100_000
    || value.next_corpus_digest === value.previous_corpus_digest) invalid();
  const { augmentation_digest: _digest, ...body } = value;
  if (digestAgentGymJson(body) !== value.augmentation_digest) invalid();
  return Object.freeze({ ...value });
}

function reference(value: string): void {
  if (typeof value !== "string" || value.length > 240 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/u.test(value)) invalid();
}
function timestamp(value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) || !Number.isFinite(Date.parse(value))) invalid();
}
function digest(value: string): void { if (!/^sha256:[0-9a-f]{64}$/u.test(value)) invalid(); }
function invalid(): never { throw new AgentGymContractError("Agent gym regression corpus augmentation is invalid."); }
