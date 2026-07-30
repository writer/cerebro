import {
  installOfflineNetworkGuard,
  proveOfflineExecution,
} from "./offline-guard.js";

installOfflineNetworkGuard();
const offlineExecution = await proveOfflineExecution();
const [
  { SLACK_WORKING_STATE_HILLCLIMB_CORPUS },
  { runSlackWorkingStateHillclimb },
] = await Promise.all([
  import("./hillclimb-corpus.js"),
  import("./hillclimb.js"),
]);
const evaluation = runSlackWorkingStateHillclimb(
  SLACK_WORKING_STATE_HILLCLIMB_CORPUS,
);
const receipt = Object.freeze({
  ...evaluation,
  offline_execution: offlineExecution,
});

process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
if (!receipt.promotion.promotion_ready) process.exitCode = 1;
