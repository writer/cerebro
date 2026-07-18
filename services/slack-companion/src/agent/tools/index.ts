import type { AgentTool } from "@earendil-works/pi-agent-core";
import { createCerebroTools, recentScaryFindings } from "./cerebro-tools.js";
import { AgentToolCatalog } from "../tool-catalog.js";
import { createAgentRuntimeTools } from "./agent-runtime-tools.js";
import { createComplianceTools } from "./compliance-tools.js";
import { createIntegrationTools } from "./integration-tools.js";
import { createMemoryTools } from "./memory-tools.js";
import { createOffboardingControlTools } from "./offboarding-control-tools.js";
import { createRuntimeCodeTools, createSelfContextTool, createSkillTools } from "./operator-tools.js";
import { createOperatorWorkflowTools } from "./operator-workflow-tools.js";
import { createPantherMcpTools } from "./panther-mcp-tools.js";
import { createResearchTools } from "./research-tools.js";
import { createSecurityCaseTools } from "./security-case-tools.js";
import { createSlackTools } from "./slack-tools.js";
import { createTicketTools } from "./ticket-tools.js";
import { boundedToolDetails, instrumentTools, TOOL_DETAILS_MAX_CHARS, toolResult } from "./tool-result.js";
import type { SecurityToolDeps } from "./types.js";

export type { SecurityToolDeps } from "./types.js";
export { boundedToolDetails, recentScaryFindings, TOOL_DETAILS_MAX_CHARS, toolResult };

export function createSecurityAgentTools(deps: SecurityToolDeps): AgentTool[] {
  const tools: AgentTool[] = [
    ...createSkillTools(deps),
    ...createRuntimeCodeTools(deps),
    ...createOperatorWorkflowTools(deps),
    ...createOffboardingControlTools(deps),
    ...createSecurityCaseTools(deps),
    ...createResearchTools(deps),
    ...createMemoryTools(deps),
    ...createSlackTools(deps),
    ...createTicketTools(deps),
    ...createIntegrationTools(deps),
    ...createPantherMcpTools(deps),
    ...createComplianceTools(deps),
    ...createCerebroTools(deps),
  ];
  tools.unshift(createSelfContextTool(deps, tools));
  let catalog: AgentToolCatalog | undefined;
  tools.push(...createAgentRuntimeTools(deps, () => catalog ?? new AgentToolCatalog(tools)));
  catalog = new AgentToolCatalog(tools);
  deps.researchState?.setAvailableTools(tools.map((tool) => tool.name));
  return instrumentTools(tools, deps.researchState);
}
