import {
  SLACK_WORKING_STATE_HILLCLIMB_CORPUS,
} from "./hillclimb-corpus.js";
import { runSlackWorkingStateHillclimb } from "./hillclimb.js";

const receipt = runSlackWorkingStateHillclimb(
  SLACK_WORKING_STATE_HILLCLIMB_CORPUS,
);
process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
if (!receipt.promotion.promotion_ready) process.exitCode = 1;
