import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import type { JsonRecord } from "../../cerebro/types.js";
import { limit, stringList, stringValue } from "./normalizers.js";
import type { SecurityToolDeps } from "./types.js";
import { safeToolResult } from "./tool-result.js";

export function createCerebroSourceTools(deps: SecurityToolDeps): AgentTool[] {
  const connectorCatalogParams = Type.Object({
    source_id: Type.Optional(Type.String()),
  });
  const connectorDetailParams = Type.Object({
    source_id: Type.String(),
  });
  const connectorActivityParams = Type.Object({
    source_id: Type.String(),
    limit: Type.Optional(Type.Number()),
  });
  const connectorCredentialsParams = Type.Object({
    source_id: Type.String(),
    runtime_id: Type.Optional(Type.String()),
    status: Type.Optional(Type.String()),
  });
  const connectorPreflightParams = Type.Object({
    source_id: Type.String(),
    runtime_id: Type.String(),
    auth_method: Type.Optional(Type.String()),
    credential_store_id: Type.Optional(Type.String()),
    config_json: Type.Optional(Type.String()),
    credential_references_json: Type.Optional(Type.String()),
    scope_policy_json: Type.Optional(Type.String()),
  });
  const connectorDefinitionsParams = Type.Object({
    definition_id: Type.Optional(Type.String()),
    stage: Type.Optional(Type.String()),
    include_versions: Type.Optional(Type.Boolean()),
    include_promotion_plan: Type.Optional(Type.Boolean()),
    limit: Type.Optional(Type.Number()),
  });
  const connectorDefinitionBodyParams = Type.Object({
    definition_json: Type.String(),
  });
  const sourceRuntimeParams = Type.Object({
    runtime_id: Type.Optional(Type.String()),
    runtime_ids: Type.Optional(Type.Array(Type.String())),
    source_id: Type.Optional(Type.String()),
    include_health: Type.Optional(Type.Boolean()),
    limit: Type.Optional(Type.Number()),
  });
  const sourceClaimsParams = Type.Object({
    runtime_id: Type.String(),
    claim_id: Type.Optional(Type.String()),
    subject_urn: Type.Optional(Type.String()),
    predicate: Type.Optional(Type.String()),
    object_urn: Type.Optional(Type.String()),
    object_value: Type.Optional(Type.String()),
    claim_type: Type.Optional(Type.String()),
    status: Type.Optional(Type.String()),
    source_event_id: Type.Optional(Type.String()),
    limit: Type.Optional(Type.Number()),
  });
  const runtimeIdParams = Type.Object({
    runtime_id: Type.String(),
  });

  return [
    {
      name: "cerebro_connector_catalog",
      label: "Cerebro connector catalog",
      description: "Read Cerebro's connector catalog, including executable built-in sources, catalog-only definitions, runtime counts, credential capability state, resource families, setup guidance, and connection methods.",
      parameters: connectorCatalogParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const args = params as { source_id?: string };
        return deps.cerebro.listConnectors({ sourceId: stringValue(args.source_id) });
      }),
    },
    {
      name: "cerebro_connector_detail",
      label: "Cerebro connector detail",
      description: "Read one Cerebro connector/source entry with runtime health summary, setup guidance, credential stores, connection methods, scope options, and recent activity.",
      parameters: connectorDetailParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const args = params as { source_id: string };
        return deps.cerebro.getConnector(args.source_id);
      }),
    },
    {
      name: "cerebro_connector_coverage",
      label: "Cerebro connector coverage",
      description: "Read Cerebro connector coverage and high-value blind spots for a tenant or one source.",
      parameters: connectorCatalogParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const args = params as { source_id?: string };
        return deps.cerebro.connectorCoverage({ sourceId: stringValue(args.source_id) });
      }),
    },
    {
      name: "cerebro_connector_activity",
      label: "Cerebro connector activity",
      description: "Read safe sync and graph activity for one Cerebro connector/source.",
      parameters: connectorActivityParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const args = params as { source_id: string; limit?: number };
        return deps.cerebro.listConnectorActivity(args.source_id, limit(args.limit, 25));
      }),
    },
    {
      name: "cerebro_connector_credentials",
      label: "Cerebro connector credentials",
      description: "Read non-secret credential metadata for one Cerebro connector/source. Never returns raw credential values.",
      parameters: connectorCredentialsParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const args = params as { source_id: string; runtime_id?: string; status?: string };
        return deps.cerebro.listConnectorCredentials(args.source_id, {
          runtimeId: stringValue(args.runtime_id),
          status: normalizeCredentialStatus(args.status),
        });
      }),
    },
    {
      name: "cerebro_connector_preflight",
      label: "Cerebro connector preflight",
      description: "Run Cerebro connector preflight with non-secret config and credential references before creating or changing a runtime. Do not send plaintext secrets.",
      parameters: connectorPreflightParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const args = params as {
          source_id: string;
          runtime_id: string;
          auth_method?: string;
          credential_store_id?: string;
          config_json?: string;
          credential_references_json?: string;
          scope_policy_json?: string;
        };
        return deps.cerebro.preflightConnector(args.source_id, {
          runtime_id: args.runtime_id,
          auth_method: stringValue(args.auth_method),
          credential_store_id: stringValue(args.credential_store_id),
          config: parseOptionalObject(args.config_json, "config_json"),
          credential_references: parseOptionalObject(args.credential_references_json, "credential_references_json"),
          scope_policy: parseOptionalObject(args.scope_policy_json, "scope_policy_json"),
        });
      }),
    },
    {
      name: "cerebro_connector_definitions",
      label: "Cerebro connector definitions",
      description: "Read Cerebro dynamic connector definitions, one definition, version history, or its Source CDK promotion plan.",
      parameters: connectorDefinitionsParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => connectorDefinitions(deps, params as ConnectorDefinitionsArgs)),
    },
    {
      name: "cerebro_connector_definition_validate",
      label: "Cerebro connector definition validate",
      description: "Validate a dynamic connector definition in Cerebro without persisting it.",
      parameters: connectorDefinitionBodyParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const args = params as { definition_json: string };
        return deps.cerebro.validateConnectorDefinition(parseRequiredObject(args.definition_json, "definition_json"));
      }),
    },
    {
      name: "cerebro_connector_definition_plan",
      label: "Cerebro connector definition plan",
      description: "Build a Cerebro Source CDK promotion plan for a dynamic connector definition without persisting it.",
      parameters: connectorDefinitionBodyParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const args = params as { definition_json: string };
        return deps.cerebro.planConnectorDefinition(parseRequiredObject(args.definition_json, "definition_json"));
      }),
    },
    {
      name: "cerebro_source_runtimes",
      label: "Cerebro source runtimes",
      description: "Read Cerebro source runtime configurations and optional consolidated health for runtime IDs or a source ID.",
      parameters: sourceRuntimeParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const args = params as {
          runtime_id?: string;
          runtime_ids?: string[];
          source_id?: string;
          include_health?: boolean;
          limit?: number;
        };
        const options = {
          runtimeId: stringValue(args.runtime_id),
          runtimeIds: stringList(args.runtime_ids),
          sourceId: stringValue(args.source_id),
          limit: limit(args.limit, 25),
        };
        const runtimes = await deps.cerebro.listSourceRuntimes(options);
        const health = args.include_health === false ? undefined : await deps.cerebro.listRuntimeHealth(options);
        return { runtimes, health };
      }),
    },
    {
      name: "cerebro_source_claims",
      label: "Cerebro source claims",
      description: "Read normalized Cerebro claims for one source runtime by subject, predicate, object, claim type, status, or source event.",
      parameters: sourceClaimsParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const args = params as SourceClaimsArgs;
        return deps.cerebro.listClaims(args.runtime_id, {
          claimId: stringValue(args.claim_id),
          subjectUrn: stringValue(args.subject_urn),
          predicate: stringValue(args.predicate),
          objectUrn: stringValue(args.object_urn),
          objectValue: stringValue(args.object_value),
          claimType: stringValue(args.claim_type),
          status: stringValue(args.status),
          sourceEventId: stringValue(args.source_event_id),
          limit: limit(args.limit, 25),
        });
      }),
    },
    {
      name: "cerebro_source_invalid_events",
      label: "Cerebro source invalid events",
      description: "Read invalid or quarantined source events for one Cerebro source runtime.",
      parameters: runtimeIdParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const args = params as { runtime_id: string };
        return deps.cerebro.listInvalidEvents(args.runtime_id);
      }),
    },
  ];
}

interface ConnectorDefinitionsArgs {
  definition_id?: string;
  stage?: string;
  include_versions?: boolean;
  include_promotion_plan?: boolean;
  limit?: number;
}

interface SourceClaimsArgs {
  runtime_id: string;
  claim_id?: string;
  subject_urn?: string;
  predicate?: string;
  object_urn?: string;
  object_value?: string;
  claim_type?: string;
  status?: string;
  source_event_id?: string;
  limit?: number;
}

async function connectorDefinitions(deps: SecurityToolDeps, args: ConnectorDefinitionsArgs): Promise<JsonRecord> {
  const definitionId = stringValue(args.definition_id);
  if (!definitionId) {
    return deps.cerebro.listConnectorDefinitions({
      stage: normalizeDefinitionStage(args.stage),
      limit: limit(args.limit, 25),
    });
  }
  const [definition, versions, promotionPlan] = await Promise.all([
    deps.cerebro.getConnectorDefinition(definitionId),
    args.include_versions ? deps.cerebro.listConnectorDefinitionVersions(definitionId) : Promise.resolve(undefined),
    args.include_promotion_plan ? deps.cerebro.connectorDefinitionPromotionPlan(definitionId) : Promise.resolve(undefined),
  ]);
  return { definition, versions, promotion_plan: promotionPlan };
}

function normalizeCredentialStatus(value: string | undefined): "pending" | "valid" | undefined {
  if (value === "pending" || value === "valid") return value;
  return undefined;
}

function normalizeDefinitionStage(value: string | undefined): "draft" | "sandbox" | "pilot" | "approved" | "certified" | undefined {
  if (value === "draft" || value === "sandbox" || value === "pilot" || value === "approved" || value === "certified") {
    return value;
  }
  return undefined;
}

function parseOptionalObject(value: string | undefined, name: string): JsonRecord | undefined {
  if (!value?.trim()) return undefined;
  return parseRequiredObject(value, name);
}

function parseRequiredObject(value: string, name: string): JsonRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${name} must be valid JSON`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${name} must be a JSON object`);
  }
  return parsed as JsonRecord;
}
