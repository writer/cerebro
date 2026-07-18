import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { cerebroGraphCypherGuide } from "../../cerebro/graph-guide.js";
import { limit } from "./normalizers.js";
import { resilientDetails, runResilient } from "./resilient-tool.js";
import type { SecurityToolDeps } from "./types.js";
import { objectValue, toolResult } from "./tool-result.js";

export function createCerebroGraphTools(deps: SecurityToolDeps): AgentTool[] {
  const graphReasonParams = Type.Object({
    question: Type.String(),
    scope_urn: Type.Optional(Type.String()),
  });
  const graphCypherSchemaParams = Type.Object({
    template_id: Type.Optional(Type.String()),
  });
  const graphCypherInvestigateParams = Type.Object({
    question: Type.Optional(Type.String()),
    scope_urn: Type.Optional(Type.String()),
    intent: Type.Optional(Type.String()),
    proposed_cypher: Type.Optional(Type.String()),
    limit: Type.Optional(Type.Number()),
    template_id: Type.Optional(Type.String()),
    schema_only: Type.Optional(Type.Boolean()),
    include_schema: Type.Optional(Type.Boolean()),
    fallback_rule_id: Type.Optional(Type.String()),
    fallback_runtime_id: Type.Optional(Type.String()),
  });
  const neighborhoodParams = Type.Object({
    root_urn: Type.String(),
    limit: Type.Optional(Type.Number()),
  });

  return [
    {
      name: "cerebro_graph_reason",
      label: "Cerebro graph reasoning",
      description: "Ask Cerebro to reason over graph context for a security triage or posture question.",
      parameters: graphReasonParams,
      execute: async (_toolCallId, params) => {
        const args = params as { question: string; scope_urn?: string };
        const response = await deps.cerebro.reasonGraph({ question: args.question, scope_urn: args.scope_urn });
        return toolResult(response);
      },
    },
    {
      name: "cerebro_graph_cypher_schema",
      label: "Cerebro graph Cypher schema",
      description: "Read Cerebro's backend-derived Cypher contract, ontology, safety rules, and query templates before drafting graph investigations.",
      parameters: graphCypherSchemaParams,
      execute: async (_toolCallId, params) => {
        const args = params as { template_id?: string };
        return toolResult(graphSchemaDetails(args.template_id));
      },
    },
    {
      name: "cerebro_graph_cypher_investigate",
      label: "Cerebro graph Cypher investigation",
      description: "Run a Cypher-shaped graph investigation through Cerebro's graph agent. Cerebro drafts, validates, executes, and returns Cypher, rows, graph probe, and summary.",
      parameters: graphCypherInvestigateParams,
      execute: async (_toolCallId, params) => {
        const args = params as GraphCypherInvestigateArgs;
        return toolResult(await graphCypherInvestigationDetails(deps, args));
      },
    },
    {
      name: "cerebro_entity_neighborhood",
      label: "Cerebro entity neighborhood",
      description: "Read neighboring graph entities for a URN mentioned by a question, alert, evidence item, or finding.",
      parameters: neighborhoodParams,
      execute: async (_toolCallId, params) => {
        const args = params as { root_urn: string; limit?: number };
        const response = await deps.cerebro.graphNeighborhood(args.root_urn, limit(args.limit, 15));
        return toolResult(response);
      },
    },
  ];
}

interface GraphCypherInvestigateArgs {
  question?: string;
  scope_urn?: string;
  intent?: string;
  proposed_cypher?: string;
  limit?: number;
  template_id?: string;
  schema_only?: boolean;
  include_schema?: boolean;
  fallback_rule_id?: string;
  fallback_runtime_id?: string;
}

function graphSchemaDetails(templateIdInput?: string): Record<string, unknown> {
  const guide = cerebroGraphCypherGuide();
  const templateId = templateIdInput?.trim();
  const details = templateId
    ? {
        ...guide,
        templates: guide.templates.filter((template) => template.id === templateId),
      }
    : guide;
  return details as unknown as Record<string, unknown>;
}

async function graphCypherInvestigationDetails(
  deps: SecurityToolDeps,
  args: GraphCypherInvestigateArgs,
): Promise<Record<string, unknown>> {
  if (args.schema_only) return graphSchemaDetails(args.template_id);
  const question = args.question?.trim();
  if (!question) return { error: "question_required", message: "Pass question or set schema_only=true." };

  const result = await runResilient<Record<string, unknown>>({
    name: "cerebro_graph_cypher_investigate",
    run: async () => {
      const response = await deps.cerebro.reasonGraph({
        question: graphInvestigationQuestion({
          question,
          intent: args.intent,
          proposedCypher: args.proposed_cypher,
          limit: limit(args.limit, 25),
        }),
        scope_urn: args.scope_urn,
      });
      return graphInvestigationResult(response);
    },
    fallbacks: args.fallback_runtime_id && args.fallback_rule_id
      ? [{
          name: "open_findings_by_rule",
          run: async () => {
            const findings = await deps.cerebro.listFindings(args.fallback_runtime_id!, {
              status: "open",
              ruleId: args.fallback_rule_id,
              limit: limit(args.limit, 25),
            });
            return {
              question,
              fallback: "open_findings_by_rule",
              row_count: findings.length,
              rows: findings,
              findings,
            };
          },
        }]
      : [],
  });

  return resilientDetails(result, args.include_schema
    ? { schema: graphSchemaDetails(args.template_id) }
    : undefined);
}

function graphInvestigationQuestion(input: {
  question: string;
  intent?: string;
  proposedCypher?: string;
  limit: number;
}): string {
  const guide = cerebroGraphCypherGuide();
  const templateIds = guide.templates.map((template) => template.id).join(", ");
  return [
    "Answer this security graph question by drafting and running backend-compatible read-only Cypher.",
    `Question: ${input.question}`,
    input.intent ? `Preferred intent or template: ${input.intent}` : `Available templates: ${templateIds}`,
    `Requested row limit: ${input.limit}`,
    "Cypher contract:",
    "- All nodes must be `:Entity {tenant_id: $tenant_id}`.",
    "- Relationships must be `:RELATION {relation: '<lowercase_relation>'}`.",
    "- Include a numeric LIMIT <= 100.",
    "- Do not use write clauses, procedures, APOC, UNWIND, range(), collect(), or unscoped node patterns.",
    input.proposedCypher ? ["Proposed Cypher shape. Use it only if it satisfies Cerebro's validator; otherwise correct it or choose a deterministic template:", input.proposedCypher].join("\n") : "",
  ].filter(Boolean).join("\n");
}

function graphInvestigationResult(response: Record<string, unknown>) {
  const rows = Array.isArray(response.rows) ? response.rows.slice(0, 20) : [];
  const cypher = objectValue(response.cypher);
  const queryPlan = objectValue(response.query_plan);
  const probe = objectValue(response.probe);
  const provenance = objectValue(response.provenance);
  return {
    question: response.question,
    answer_markdown: response.answer_markdown,
    cypher: typeof cypher?.cypher === "string" ? cypher.cypher : undefined,
    validator: cypher?.validator,
    query_plan: queryPlan?.plan,
    query_source: queryPlan?.source,
    query_diagnostics: queryPlan?.diagnostics,
    probe,
    row_count: Array.isArray(response.rows) ? response.rows.length : 0,
    rows,
    citations: response.citations,
    citation_validation: response.citation_validation,
    unsupported_query: response.unsupported_query,
    provenance,
  };
}
