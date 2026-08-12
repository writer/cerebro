import { BedrockHostedModel } from "./bedrock-model.js";
import { SLACK_WORKING_STATE_HILLCLIMB_CORPUS } from "./hillclimb-corpus.js";
import { runHostedSlackWorkingStateHillclimb } from "./hosted-hillclimb.js";

const DEPLOYED_OPUS_MODEL_ID = "us.anthropic.claude-opus-4-8";
const INDEPENDENT_JUDGE_MODEL_ID = "us.anthropic.claude-opus-5";
const region = required("CEREBRO_SLACK_HILLCLIMB_REGION");
const generatorModelId = optional(
  "CEREBRO_SLACK_HILLCLIMB_GENERATOR_MODEL_ID",
) ?? DEPLOYED_OPUS_MODEL_ID;
const judgeModelId = optional("CEREBRO_SLACK_HILLCLIMB_JUDGE_MODEL_ID")
  ?? INDEPENDENT_JUDGE_MODEL_ID;
const generatorModel = new BedrockHostedModel(region);
const judgeModel = new BedrockHostedModel(region);

try {
  const receipt = await runHostedSlackWorkingStateHillclimb(
    SLACK_WORKING_STATE_HILLCLIMB_CORPUS,
    {
      generator_model_id: generatorModelId,
      judge_model_id: judgeModelId,
      region,
    },
    { generator: generatorModel, judge: judgeModel },
  );
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
  if (!receipt.promotion.promotion_ready) process.exitCode = 1;
} finally {
  generatorModel.destroy();
  judgeModel.destroy();
}

function required(name: string): string {
  const value = optional(name);
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function optional(name: string): string | undefined {
  return process.env[name]?.trim() || undefined;
}
