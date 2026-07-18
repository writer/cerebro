import { buildAutonomyConfig } from "./autonomy.js";
import { buildA2AConfig } from "./a2a.js";
import { buildCerebroConfig } from "./cerebro.js";
import { buildCodeConfig } from "./code.js";
import { buildCodeModeConfig } from "./code-mode.js";
import { buildComplianceContextConfig } from "./compliance-context.js";
import { buildCoordinationConfig } from "./coordination.js";
import { buildEvidenceCasConfig } from "./evidence-cas.js";
import { envSchema } from "./env.js";
import { buildInfisicalConfig } from "./infisical.js";
import { buildImprovementConfig } from "./improvement.js";
import { buildLearningConfig } from "./learning.js";
import { buildPantherMcpConfig } from "./panther-mcp.js";
import { buildSchedulesConfig } from "./schedules.js";
import { buildSelfRepairConfig } from "./self-repair.js";
import { buildSlackConfig, validateSlackConfig } from "./slack.js";
import { buildTelemetryConfig } from "./telemetry.js";
import { buildTicketingConfig } from "./ticketing.js";
import { buildTriageConfig } from "./triage.js";
import type { AppConfig } from "./types.js";

export type { ActorMapping, AppConfig, CodeModeConfig, ProactiveSlackChannelPolicy } from "./types.js";

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = envSchema.parse(env);
  validateSlackConfig(parsed);

  return {
    nodeEnv: parsed.NODE_ENV,
    port: parsed.PORT,
    slack: buildSlackConfig(parsed),
    cerebro: buildCerebroConfig(parsed),
    evidenceCas: buildEvidenceCasConfig(parsed),
    infisical: buildInfisicalConfig(parsed),
    pantherMcp: buildPantherMcpConfig(parsed),
    triage: buildTriageConfig(parsed),
    learning: buildLearningConfig(parsed),
    code: buildCodeConfig(parsed),
    codeMode: buildCodeModeConfig(parsed),
    ticketing: buildTicketingConfig(parsed),
    complianceContext: buildComplianceContextConfig(parsed),
    selfRepair: buildSelfRepairConfig(parsed),
    improvement: buildImprovementConfig(parsed),
    autonomy: buildAutonomyConfig(parsed),
    schedules: buildSchedulesConfig(parsed),
    telemetry: buildTelemetryConfig(parsed),
    coordination: buildCoordinationConfig(parsed),
    a2a: buildA2AConfig(parsed),
  };
}
