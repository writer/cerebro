import { createHash } from "node:crypto";
import { Client as CerebroSdkClient } from "@writer/cerebro-sdk";
import type { Claim } from "@writer/cerebro-sdk";
import type { AppConfig } from "../config/index.js";
import type { SlackActor } from "../auth.js";
import {
  annotateMainDependency,
  annotateSpan,
  telemetryErrorKind,
  withTelemetrySpan,
} from "../telemetry.js";
import { parseAgentControlPlaneResponse } from "./agent-control-plane.js";
import {
  parsePolicyCandidate,
  parsePolicyCandidateList,
  type PolicyCandidate,
  type PolicyCandidateCreateRequest,
  type PolicyCandidateStatus,
} from "./policy-candidates.js";
import type {
  AgentControlPlane,
  ClaimVerificationRequest,
  ClaimVerification,
  DecisionPacket,
  DecisionPacketBuildRequest,
  Finding,
  FindingEvidence,
  GraphActionRequest,
  GraphReasonRequest,
  JsonRecord,
  RuntimeHealth,
  RuntimeResponseCapability,
} from "./types.js";

type CredentialName = "read" | "findings" | "source" | "runtimeResponse" | "graphActions";

export class CerebroClient {
  private readonly sdk: Record<CredentialName, CerebroSdkClient>;
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly config: AppConfig, options: { fetchImpl?: typeof fetch } = {}) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sdk = {
      read: this.newSdkClient("read"),
      findings: this.newSdkClient("findings"),
      source: this.newSdkClient("source"),
      runtimeResponse: this.newSdkClient("runtimeResponse"),
      graphActions: this.newSdkClient("graphActions"),
    };
  }

  async ensureCompanionRuntime(): Promise<void> {
    const integration = this.sdk.source.integration({
      runtimeId: this.config.cerebro.companionRuntimeId,
      tenantId: this.config.cerebro.tenantId,
      integration: "slack-companion",
    });
    await integration.ensureRuntime({ owner: "cerebro-slack-companion" });
  }

  async recordInteraction(input: {
    actor: SlackActor;
    action: string;
    channelId?: string;
    status: "received" | "completed" | "failed";
    subject?: string;
    details?: Record<string, string>;
  }): Promise<void> {
    const integration = this.sdk.source.integration({
      runtimeId: this.config.cerebro.companionRuntimeId,
      tenantId: this.config.cerebro.tenantId,
      integration: "slack-companion",
    });
    const eventId = stableHash([input.actor.slackUserId, input.action, input.subject ?? "", new Date().toISOString()]);
    const subject = integration.ref("slack_interaction", eventId, input.action);
    const actor = integration.ref("slack_user", input.actor.slackUserId, input.actor.displayName ?? input.actor.slackUserId);
    const claims: Claim[] = [
      integration.exists(subject, { source_event_id: eventId }),
      integration.rel(subject, "performed_by", actor, { source_event_id: eventId }),
      integration.attr(subject, "action", input.action, { source_event_id: eventId }),
      integration.attr(subject, "status", input.status, { source_event_id: eventId }),
      integration.attr(subject, "actor_id", input.actor.actorId, { source_event_id: eventId }),
    ];
    if (input.channelId) {
      claims.push(integration.attr(subject, "slack_channel_id", input.channelId, { source_event_id: eventId }));
    }
    for (const [key, value] of Object.entries(input.details ?? {})) {
      claims.push(integration.attr(subject, key, value, { source_event_id: eventId }));
    }
    await integration.writeClaims(claims);
  }

  async listRuntimeHealth(options: {
    runtimeId?: string;
    runtimeIds?: string[];
    sourceId?: string;
    limit?: number;
  } = {}): Promise<RuntimeHealth[]> {
    const query = this.runtimeQuery(options);
    const response = await this.requestJson<JsonRecord>("read", "GET", `/source-runtimes/health?${query}`);
    return arrayFrom(response, "runtimes", "health", "items") as RuntimeHealth[];
  }

  async listConnectors(options: { sourceId?: string } = {}): Promise<JsonRecord> {
    const query = new URLSearchParams({ tenant_id: this.config.cerebro.tenantId });
    if (options.sourceId) query.set("source_id", options.sourceId);
    return this.requestJson<JsonRecord>("read", "GET", `/connectors?${query}`);
  }

  async getConnector(sourceId: string): Promise<JsonRecord> {
    const query = new URLSearchParams({ tenant_id: this.config.cerebro.tenantId });
    return this.requestJson<JsonRecord>("read", "GET", `/connectors/${encodeURIComponent(sourceId)}?${query}`);
  }

  async listConnectorActivity(sourceId: string, limit = 20): Promise<JsonRecord> {
    const query = new URLSearchParams({ tenant_id: this.config.cerebro.tenantId, limit: String(limit) });
    return this.requestJson<JsonRecord>("read", "GET", `/connectors/${encodeURIComponent(sourceId)}/activity?${query}`);
  }

  async listConnectorCredentials(sourceId: string, options: {
    runtimeId?: string;
    status?: "pending" | "valid";
  } = {}): Promise<JsonRecord> {
    const query = new URLSearchParams({ tenant_id: this.config.cerebro.tenantId });
    if (options.runtimeId) query.set("runtime_id", options.runtimeId);
    if (options.status) query.set("status", options.status);
    return this.requestJson<JsonRecord>("read", "GET", `/connectors/${encodeURIComponent(sourceId)}/credentials?${query}`);
  }

  async preflightConnector(sourceId: string, request: JsonRecord): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("source", "POST", `/connectors/${encodeURIComponent(sourceId)}/preflight`, {
      ...request,
      tenant_id: this.config.cerebro.tenantId,
    });
  }

  async connectorCoverage(options: { sourceId?: string } = {}): Promise<JsonRecord> {
    const query = new URLSearchParams({ tenant_id: this.config.cerebro.tenantId });
    if (options.sourceId) query.set("source_id", options.sourceId);
    return this.requestJson<JsonRecord>("read", "GET", `/connectors/coverage?${query}`);
  }

  async listConnectorDefinitions(options: {
    stage?: "draft" | "sandbox" | "pilot" | "approved" | "certified";
    limit?: number;
  } = {}): Promise<JsonRecord> {
    const query = new URLSearchParams({ tenant_id: this.config.cerebro.tenantId });
    if (options.stage) query.set("stage", options.stage);
    if (options.limit) query.set("limit", String(options.limit));
    return this.requestJson<JsonRecord>("read", "GET", `/connector-definitions?${query}`);
  }

  async getConnectorDefinition(definitionId: string): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("read", "GET", `/connector-definitions/${encodeURIComponent(definitionId)}`);
  }

  async listConnectorDefinitionVersions(definitionId: string): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("read", "GET", `/connector-definitions/${encodeURIComponent(definitionId)}/versions`);
  }

  async connectorDefinitionPromotionPlan(definitionId: string): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("read", "GET", `/connector-definitions/${encodeURIComponent(definitionId)}/promotion-plan`);
  }

  async validateConnectorDefinition(definition: JsonRecord): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("read", "POST", "/connector-definitions/validate", definition);
  }

  async planConnectorDefinition(definition: JsonRecord): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("read", "POST", "/connector-definitions/plan", { definition });
  }

  async previewConnectorDefinition(request: JsonRecord): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("source", "POST", "/connector-definitions/preview", {
      ...request,
      tenant_id: this.config.cerebro.tenantId,
    });
  }

  async listSourceRuntimes(options: {
    runtimeId?: string;
    runtimeIds?: string[];
    sourceId?: string;
    limit?: number;
  } = {}): Promise<JsonRecord> {
    const query = this.runtimeQuery(options);
    return this.requestJson<JsonRecord>("read", "GET", `/source-runtimes?${query}`);
  }

  async getSourceRuntime(runtimeId: string): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("read", "GET", `/source-runtimes/${encodeURIComponent(runtimeId)}`);
  }

  async listClaims(runtimeId: string, options: {
    claimId?: string;
    subjectUrn?: string;
    predicate?: string;
    objectUrn?: string;
    objectValue?: string;
    claimType?: string;
    status?: string;
    sourceEventId?: string;
    limit?: number;
  } = {}): Promise<JsonRecord> {
    const query = new URLSearchParams();
    if (options.claimId) query.set("claim_id", options.claimId);
    if (options.subjectUrn) query.set("subject_urn", options.subjectUrn);
    if (options.predicate) query.set("predicate", options.predicate);
    if (options.objectUrn) query.set("object_urn", options.objectUrn);
    if (options.objectValue) query.set("object_value", options.objectValue);
    if (options.claimType) query.set("claim_type", options.claimType);
    if (options.status) query.set("status", options.status);
    if (options.sourceEventId) query.set("source_event_id", options.sourceEventId);
    if (options.limit) query.set("limit", String(options.limit));
    const suffix = query.toString() ? `?${query}` : "";
    return this.requestJson<JsonRecord>("read", "GET", `/source-runtimes/${encodeURIComponent(runtimeId)}/claims${suffix}`);
  }

  async listInvalidEvents(runtimeId: string): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("read", "GET", `/source-runtimes/${encodeURIComponent(runtimeId)}/invalid-events`);
  }

  async listFindings(runtimeId: string, options: {
    status?: "open" | "resolved" | "suppressed";
    severity?: string;
    findingId?: string;
    ruleId?: string;
    order?: "last_observed" | "priority" | "risk_score";
    limit?: number;
  } = {}): Promise<Finding[]> {
    const query = new URLSearchParams();
    query.set("status", options.status ?? "open");
    query.set("order", options.order ?? "priority");
    query.set("limit", String(options.limit ?? 5));
    if (options.severity) query.set("severity", options.severity);
    if (options.findingId) query.set("finding_id", options.findingId);
    if (options.ruleId) query.set("rule_id", options.ruleId);
    const response = await this.requestJson<JsonRecord>("read", "GET", `/source-runtimes/${encodeURIComponent(runtimeId)}/findings?${query}`);
    return arrayFrom(response, "findings") as Finding[];
  }

  async listFindingEvidence(runtimeId: string, findingId: string, limit = 5): Promise<FindingEvidence[]> {
    const query = new URLSearchParams({ finding_id: findingId, limit: String(limit) });
    const response = await this.requestJson<JsonRecord>("read", "GET", `/source-runtimes/${encodeURIComponent(runtimeId)}/finding-evidence?${query}`);
    return arrayFrom(response, "evidence") as FindingEvidence[];
  }

  async buildEvidencePacket(request: JsonRecord): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("read", "POST", "/api/v1/agent-platform/evidence-packets", {
      ...request,
      tenant_id: this.config.cerebro.tenantId,
    });
  }

  async reasonGraph(request: GraphReasonRequest): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("read", "POST", "/api/v1/agent-platform/graph/reason", {
      ...request,
      tenant_id: this.config.cerebro.tenantId,
    });
  }

  async verifyAgentClaim(request: ClaimVerificationRequest): Promise<ClaimVerification> {
    return this.requestJson<ClaimVerification>("read", "POST", "/api/v1/agent-platform/claims/verify", {
      ...request,
      tenant_id: this.config.cerebro.tenantId,
    });
  }

  async getAgentControlPlane(): Promise<AgentControlPlane> {
    const response = await this.requestJson<unknown>("read", "GET", "/api/v1/agent-platform/security-control-plane");
    return parseAgentControlPlaneResponse(response);
  }

  async buildDecisionPacket(request: DecisionPacketBuildRequest): Promise<DecisionPacket> {
    return this.requestJson<DecisionPacket>("read", "POST", "/api/v1/platform/decision-packets", request);
  }

  async getDecisionPacket(packetId: string): Promise<DecisionPacket> {
    return this.requestJson<DecisionPacket>("read", "GET", `/api/v1/platform/decision-packets/${encodeURIComponent(packetId)}`);
  }

  async createPolicyCandidate(request: PolicyCandidateCreateRequest): Promise<PolicyCandidate> {
    const response = await this.requestJson<unknown>("findings", "POST", "/policy-candidates", {
      tenant_id: this.config.cerebro.tenantId,
      ...request,
    });
    return parsePolicyCandidate(response);
  }

  async listPolicyCandidates(options: { status?: PolicyCandidateStatus; limit?: number } = {}): Promise<PolicyCandidate[]> {
    const query = new URLSearchParams({ tenant_id: this.config.cerebro.tenantId });
    if (options.status) query.set("status", options.status);
    if (options.limit) query.set("limit", String(options.limit));
    const response = await this.requestJson<unknown>("read", "GET", `/policy-candidates?${query}`);
    return parsePolicyCandidateList(response);
  }

  async getPolicyCandidate(candidateId: string): Promise<PolicyCandidate> {
    const response = await this.requestJson<unknown>("read", "GET", `/policy-candidates/${encodeURIComponent(candidateId)}`);
    return parsePolicyCandidate(response);
  }

  async provePolicyCandidate(candidateId: string): Promise<PolicyCandidate> {
    const response = await this.requestJson<unknown>("findings", "POST", `/policy-candidates/${encodeURIComponent(candidateId)}/prove`);
    return parsePolicyCandidate(response);
  }

  async shadowPolicyCandidate(candidateId: string): Promise<PolicyCandidate> {
    const response = await this.requestJson<unknown>("findings", "POST", `/policy-candidates/${encodeURIComponent(candidateId)}/shadow`);
    return parsePolicyCandidate(response);
  }

  async graphNeighborhood(rootUrn: string, limit = 10): Promise<JsonRecord> {
    return this.sdk.read.getEntityNeighborhood(rootUrn, limit) as Promise<JsonRecord>;
  }

  async syncRuntime(runtimeId: string): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("source", "POST", `/source-runtimes/${encodeURIComponent(runtimeId)}/sync`);
  }

  async runGraphIngest(runtimeId: string): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("source", "POST", `/source-runtimes/${encodeURIComponent(runtimeId)}/graph-ingest-runs`);
  }

  async evaluateFindings(runtimeId: string): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("source", "POST", `/source-runtimes/${encodeURIComponent(runtimeId)}/findings/evaluate`);
  }

  async addFindingNote(findingId: string, note: string): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("findings", "POST", `/findings/${encodeURIComponent(findingId)}/notes`, { note });
  }

  async assignFinding(findingId: string, assignee: string): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("findings", "PUT", `/findings/${encodeURIComponent(findingId)}/assign`, { assignee });
  }

  async setFindingDueDate(findingId: string, dueAt: string): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("findings", "PUT", `/findings/${encodeURIComponent(findingId)}/due`, { due_at: dueAt });
  }

  async resolveFinding(findingId: string, reason: string): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("findings", "POST", `/findings/${encodeURIComponent(findingId)}/resolve`, { reason });
  }

  async suppressFinding(findingId: string, reason: string): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("findings", "POST", `/findings/${encodeURIComponent(findingId)}/suppress`, { reason });
  }

  async linkFindingTicket(findingId: string, ticket: { url: string; name?: string; externalId?: string }): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("findings", "POST", `/findings/${encodeURIComponent(findingId)}/tickets`, {
      url: ticket.url,
      name: ticket.name,
      external_id: ticket.externalId,
    });
  }

  async listRuntimeResponseCapabilities(): Promise<RuntimeResponseCapability[]> {
    const response = await this.requestJson<JsonRecord>("read", "GET", "/platform/runtime-response/capabilities");
    return arrayFrom(response, "capabilities") as RuntimeResponseCapability[];
  }

  async executeGraphAction(request: GraphActionRequest): Promise<JsonRecord> {
    return this.requestJson<JsonRecord>("graphActions", "POST", "/platform/graph/actions", request);
  }

  stableIdempotencyKey(parts: string[]): string {
    return stableHash(parts);
  }

  private newSdkClient(scope: CredentialName): CerebroSdkClient {
    return new CerebroSdkClient({
      baseUrl: this.config.cerebro.baseUrl,
      apiKey: this.apiKey(scope),
      userAgent: "cerebro-slack-companion",
      fetchImpl: this.requestWithTimeout,
    });
  }

  private readonly requestWithTimeout: typeof fetch = (input, init = {}) => {
    const timeoutSignal = AbortSignal.timeout(this.config.cerebro.requestTimeoutMs);
    const signal = init.signal ? AbortSignal.any([init.signal, timeoutSignal]) : timeoutSignal;
    return this.fetchImpl(input, { ...init, signal });
  };

  private async requestJson<T>(scope: CredentialName, method: string, path: string, body?: unknown): Promise<T> {
    const route = normalizeCerebroRoute(path);
    return withTelemetrySpan("cerebro.http.request", {
      component: "cerebro-client",
      operation: "http_request",
      "cerebro.credential.scope": scope,
      "http.request.method": method,
      "http.route": route,
      "http.request.body.present": body !== undefined,
      "http.request.body.size": body === undefined ? 0 : JSON.stringify(body).length,
    }, async (span) => {
    const headers = new Headers();
    headers.set("Accept", "application/json");
    headers.set("User-Agent", "cerebro-slack-companion");
    headers.set("Authorization", `Bearer ${this.apiKey(scope)}`);
    headers.set("X-Cerebro-Tenant", this.config.cerebro.tenantId);
    let requestBody: string | undefined;
    if (body !== undefined) {
      headers.set("Content-Type", "application/json");
      requestBody = JSON.stringify(body);
    }
    try {
      const response = await this.requestWithTimeout(`${this.config.cerebro.baseUrl}${path}`, {
        method,
        headers,
        body: requestBody,
      });
      const text = await response.text();
      annotateSpan(span, {
        "http.response.status_code": response.status,
        "http.response.status_class": httpStatusClass(response.status),
        "http.response.body.size": text.length,
      });
      annotateMainDependency("cerebro", "cerebro-client", route, response.ok ? "completed" : "failed", {
        "http.response.status_class": httpStatusClass(response.status),
      });
      if (!response.ok) {
        throw new Error(`Cerebro request failed with status ${response.status}`);
      }
      return (text ? JSON.parse(text) : {}) as T;
    } catch (error) {
      annotateSpan(span, { error_kind: telemetryErrorKind(error) });
      annotateMainDependency("cerebro", "cerebro-client", route, "failed", {
        error_kind: telemetryErrorKind(error),
      });
      throw error;
    }
    }, { errorEventName: "cerebro.http.error" });
  }

  private runtimeQuery(options: {
    runtimeId?: string;
    runtimeIds?: string[];
    sourceId?: string;
    limit?: number;
  }): URLSearchParams {
    const query = new URLSearchParams({ tenant_id: this.config.cerebro.tenantId });
    if (options.runtimeId) query.set("runtime_id", options.runtimeId);
    if (options.runtimeIds?.length) query.set("runtime_ids", options.runtimeIds.join(","));
    if (options.sourceId) query.set("source_id", options.sourceId);
    if (options.limit) query.set("limit", String(options.limit));
    return query;
  }

  private apiKey(scope: CredentialName): string {
    const keys = this.config.cerebro.apiKeys;
    switch (scope) {
      case "read":
        return keys.read;
      case "findings":
        return keys.findings ?? keys.read;
      case "source":
        return keys.source ?? keys.read;
      case "runtimeResponse":
        return keys.runtimeResponse ?? keys.read;
      case "graphActions":
        return keys.graphActions ?? keys.read;
    }
  }
}

function arrayFrom(record: JsonRecord, ...keys: string[]): unknown[] {
  for (const key of keys) {
    const value = record[key];
    if (Array.isArray(value)) {
      return value;
    }
  }
  return [];
}

function stableHash(parts: string[]): string {
  return createHash("sha256").update(parts.join("\u0000")).digest("hex").slice(0, 40);
}

function normalizeCerebroRoute(path: string): string {
  const pathname = path.split("?")[0] ?? path;
  if ([
    "/connectors/coverage",
    "/connector-definitions/validate",
    "/connector-definitions/preview",
    "/connector-definitions/plan",
  ].includes(pathname)) {
    return pathname;
  }
  return pathname
    .replace(/\/source-runtimes\/[^/?]+/g, "/source-runtimes/{runtimeID}")
    .replace(/\/connectors\/[^/?]+/g, "/connectors/{sourceID}")
    .replace(/\/connector-definitions\/[^/?]+/g, "/connector-definitions/{definitionID}")
    .replace(/\/findings\/[^/?]+/g, "/findings/{findingID}")
    .replace(/\/platform\/jobs\/[^/?]+/g, "/platform/jobs/{jobID}")
    .replace(/\/policy-candidates\/[^/?]+/g, "/policy-candidates/{candidateID}")
    .replace(/\/api\/v1\/platform\/decision-packets\/[^/?]+/g, "/api/v1/platform/decision-packets/{packetID}")
    .replace(/\/entities\/[^/?]+/g, "/entities/{entityID}");
}

function httpStatusClass(statusCode: number): string {
  if (statusCode >= 100 && statusCode < 200) return "1xx";
  if (statusCode >= 200 && statusCode < 300) return "2xx";
  if (statusCode >= 300 && statusCode < 400) return "3xx";
  if (statusCode >= 400 && statusCode < 500) return "4xx";
  if (statusCode >= 500 && statusCode < 600) return "5xx";
  return statusCode === 0 ? "none" : "other";
}
