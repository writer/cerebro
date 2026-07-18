import type { AgentTool } from "@earendil-works/pi-agent-core";
import { createCerebroAgentPlatformTools } from "./cerebro-agent-platform-tools.js";
import { createCerebroFindingTools } from "./cerebro-finding-tools.js";
import { createCerebroGraphTools } from "./cerebro-graph-tools.js";
import { createCerebroPanopticonTools } from "./cerebro-panopticon-tools.js";
import { createCerebroPolicyCandidateTools } from "./cerebro-policy-candidate-tools.js";
import { createCerebroPostureTools } from "./cerebro-posture-tools.js";
import { createCerebroRuntimeTools } from "./cerebro-runtime-tools.js";
import { createCerebroSourceTools } from "./cerebro-source-tools.js";
import type { SecurityToolDeps } from "./types.js";

export { findingInvestigation } from "./cerebro-finding-tools.js";
export { recentScaryFindings } from "./cerebro-posture-tools.js";

export function createCerebroTools(deps: SecurityToolDeps): AgentTool[] {
  return [
    ...createCerebroAgentPlatformTools(deps),
    ...createCerebroGraphTools(deps),
    ...createCerebroPanopticonTools(deps),
    ...createCerebroPolicyCandidateTools(deps),
    ...createCerebroPostureTools(deps),
    ...createCerebroRuntimeTools(deps),
    ...createCerebroSourceTools(deps),
    ...createCerebroFindingTools(deps),
  ];
}
