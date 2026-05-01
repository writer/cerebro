export class APIError extends Error {
    statusCode;
    code;
    constructor(statusCode, message, code) {
        super(`api request failed (${statusCode}${code ? ` ${code}` : ""}): ${message}`);
        this.statusCode = statusCode;
        this.code = code;
    }
}
export class Client {
    baseUrl;
    apiKey;
    userAgent;
    fetchImpl;
    constructor(config) {
        if (!config.baseUrl) {
            throw new Error("baseUrl is required");
        }
        this.baseUrl = config.baseUrl.replace(/\/$/, "");
        this.apiKey = config.apiKey;
        this.userAgent = config.userAgent ?? "cerebro-sdk-typescript";
        this.fetchImpl = config.fetchImpl ?? fetch;
    }
    async listTools() {
        return this.requestJson("GET", "/api/v1/agent-sdk/tools");
    }
    async callTool(toolId, args) {
        return this.requestJson("POST", `/api/v1/agent-sdk/tools/${encodeURIComponent(toolId)}:call`, args);
    }
    async runReport(payload) {
        return this.requestJson("POST", "/api/v1/agent-sdk/report", payload);
    }
    async getProtectedResourceMetadata() {
        return this.requestJson("GET", "/.well-known/oauth-protected-resource");
    }
    async putSourceRuntime(runtimeId, runtime) {
        return this.requestJson("PUT", `/source-runtimes/${encodeURIComponent(runtimeId)}`, { runtime });
    }
    async getSourceRuntime(runtimeId) {
        return this.requestJson("GET", `/source-runtimes/${encodeURIComponent(runtimeId)}`);
    }
    async writeClaims(runtimeId, claims, options = {}) {
        return this.requestJson("POST", `/source-runtimes/${encodeURIComponent(runtimeId)}/claims`, {
            ...options,
            claims,
        });
    }
    async listClaims(runtimeId, options = {}) {
        const query = new URLSearchParams();
        for (const [key, value] of Object.entries(options)) {
            if (value === undefined || value === null || value === "") {
                continue;
            }
            query.set(key, String(value));
        }
        const suffix = query.toString() ? `?${query.toString()}` : "";
        return this.requestJson("GET", `/source-runtimes/${encodeURIComponent(runtimeId)}/claims${suffix}`);
    }
    async getEntityNeighborhood(rootUrn, limit = 0) {
        const normalizedRootUrn = rootUrn.trim();
        if (!normalizedRootUrn) {
            throw new Error("rootUrn is required");
        }
        const query = new URLSearchParams({ root_urn: normalizedRootUrn });
        if (limit > 0) {
            query.set("limit", String(limit));
        }
        return this.requestJson("GET", `/graph/neighborhood?${query.toString()}`);
    }
    integration(options) {
        return new IntegrationClient(this, options);
    }
    async listManagedCredentials() {
        return this.requestJson("GET", "/api/v1/admin/agent-sdk/credentials");
    }
    async getManagedCredential(credentialId) {
        return this.requestJson("GET", `/api/v1/admin/agent-sdk/credentials/${encodeURIComponent(credentialId)}`);
    }
    async createManagedCredential(payload) {
        return this.requestJson("POST", "/api/v1/admin/agent-sdk/credentials", payload);
    }
    async rotateManagedCredential(credentialId, payload = {}) {
        return this.requestJson("POST", `/api/v1/admin/agent-sdk/credentials/${encodeURIComponent(credentialId)}:rotate`, payload);
    }
    async revokeManagedCredential(credentialId, payload = {}) {
        return this.requestJson("POST", `/api/v1/admin/agent-sdk/credentials/${encodeURIComponent(credentialId)}:revoke`, payload);
    }
    async mcp(payload, sessionId = "") {
        const headers = {};
        if (sessionId) {
            headers["Mcp-Session-Id"] = sessionId;
        }
        const { payload: response, headers: responseHeaders } = await this.requestJsonWithHeaders("POST", "/api/v1/mcp", payload, headers);
        return { response, sessionId: responseHeaders.get("Mcp-Session-Id") ?? "" };
    }
    async openMCPStream(sessionId = "") {
        const headers = { Accept: "text/event-stream" };
        if (sessionId) {
            headers["Mcp-Session-Id"] = sessionId;
        }
        return this.requestRaw("GET", "/api/v1/mcp", undefined, headers);
    }
    async openReportRunStream(statusPath) {
        return this.requestRaw("GET", `${statusPath}/stream`, undefined, { Accept: "text/event-stream" });
    }
    async accessReview(args) {
        return this.callTool("cerebro_access_review", args);
    }
    async actuateRecommendation(args) {
        return this.callTool("cerebro_actuate_recommendation", args);
    }
    async aiWorkloads(args) {
        return this.callTool("cerebro_ai_workloads", args);
    }
    async annotate(args) {
        return this.callTool("cerebro_annotate", args);
    }
    async autonomousCredentialResponse(args) {
        return this.callTool("cerebro_autonomous_credential_response", args);
    }
    async autonomousWorkflowApprove(args) {
        return this.callTool("cerebro_autonomous_workflow_approve", args);
    }
    async autonomousWorkflowStatus(args) {
        return this.callTool("cerebro_autonomous_workflow_status", args);
    }
    async blastRadius(args) {
        return this.callTool("cerebro_blast_radius", args);
    }
    async check(args) {
        return this.callTool("cerebro_check", args);
    }
    async claim(args) {
        return this.callTool("cerebro_claim", args);
    }
    async context(args) {
        return this.callTool("cerebro_context", args);
    }
    async correlateEvents(args) {
        return this.callTool("cerebro_correlate_events", args);
    }
    async decide(args) {
        return this.callTool("cerebro_decide", args);
    }
    async diff(args) {
        return this.callTool("cerebro_diff", args);
    }
    async entityHistory(args) {
        return this.callTool("cerebro_entity_history", args);
    }
    async executionStatus(args) {
        return this.callTool("cerebro_execution_status", args);
    }
    async findings(args) {
        return this.callTool("cerebro_findings", args);
    }
    async graphChangelog(args) {
        return this.callTool("cerebro_graph_changelog", args);
    }
    async graphQuery(args) {
        return this.callTool("cerebro_graph_query", args);
    }
    async graphSimulate(args) {
        return this.callTool("cerebro_graph_simulate", args);
    }
    async identityCalibration(args) {
        return this.callTool("cerebro_identity_calibration", args);
    }
    async identityReview(args) {
        return this.callTool("cerebro_identity_review", args);
    }
    async keyPersonRisk(args) {
        return this.callTool("cerebro_key_person_risk", args);
    }
    async leverage(args) {
        return this.callTool("cerebro_leverage", args);
    }
    async nlq(args) {
        return this.callTool("cerebro_nlq", args);
    }
    async observe(args) {
        return this.callTool("cerebro_observe", args);
    }
    async outcome(args) {
        return this.callTool("cerebro_outcome", args);
    }
    async quality(args) {
        return this.callTool("cerebro_quality", args);
    }
    async reconstruct(args) {
        return this.callTool("cerebro_reconstruct", args);
    }
    async report(args) {
        return this.callTool("cerebro_report", args);
    }
    async resolveIdentity(args) {
        return this.callTool("cerebro_resolve_identity", args);
    }
    async riskScore(args) {
        return this.callTool("cerebro_risk_score", args);
    }
    async simulate(args) {
        return this.callTool("cerebro_simulate", args);
    }
    async splitIdentity(args) {
        return this.callTool("cerebro_split_identity", args);
    }
    async templates(args) {
        return this.callTool("cerebro_templates", args);
    }
    async timeline(args) {
        return this.callTool("cerebro_timeline", args);
    }
    async requestJson(method, path, body, headers = {}) {
        const { payload } = await this.requestJsonWithHeaders(method, path, body, headers);
        return payload;
    }
    async requestJsonWithHeaders(method, path, body, headers = {}) {
        const response = await this.requestRaw(method, path, body, headers);
        const text = await response.text();
        return { payload: (text ? JSON.parse(text) : null), headers: response.headers };
    }
    async requestRaw(method, path, body, headers = {}) {
        const initHeaders = new Headers(headers);
        initHeaders.set("Accept", initHeaders.get("Accept") ?? "application/json");
        initHeaders.set("User-Agent", initHeaders.get("User-Agent") ?? this.userAgent);
        if (this.apiKey) {
            initHeaders.set("Authorization", `Bearer ${this.apiKey}`);
        }
        let requestBody;
        if (body !== undefined) {
            initHeaders.set("Content-Type", initHeaders.get("Content-Type") ?? "application/json");
            requestBody = JSON.stringify(body);
        }
        const response = await this.fetchImpl(`${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`, {
            method,
            headers: initHeaders,
            body: requestBody,
        });
        if (!response.ok) {
            const text = await response.text();
            try {
                const decoded = text ? JSON.parse(text) : {};
                throw new APIError(response.status, decoded.error ?? text, decoded.code);
            }
            catch (error) {
                if (error instanceof APIError) {
                    throw error;
                }
                throw new APIError(response.status, text || response.statusText);
            }
        }
        return response;
    }
}
export class IntegrationClient {
    client;
    runtimeId;
    tenantId;
    integrationName;
    constructor(client, options) {
        if (!options.runtimeId) {
            throw new Error("runtimeId is required");
        }
        if (!options.tenantId) {
            throw new Error("tenantId is required");
        }
        if (!options.integration) {
            throw new Error("integration is required");
        }
        this.client = client;
        this.runtimeId = options.runtimeId;
        this.tenantId = options.tenantId;
        this.integrationName = options.integration;
    }
    async ensureRuntime(config = {}) {
        return this.client.putSourceRuntime(this.runtimeId, {
            source_id: "sdk",
            tenant_id: this.tenantId,
            config: {
                integration: this.integrationName,
                ...config,
            },
        });
    }
    async writeClaims(claims, options = {}) {
        return this.client.writeClaims(this.runtimeId, claims, options);
    }
    async listClaims(options = {}) {
        return this.client.listClaims(this.runtimeId, options);
    }
    async graphNeighborhood(root, limit = 0) {
        const rootUrn = typeof root === "string" ? root.trim() : root.urn.trim();
        return this.client.getEntityNeighborhood(rootUrn, limit);
    }
    async graphLayering(roots, limit = 0) {
        const layering = {};
        const seen = new Set();
        for (const root of roots) {
            const rootUrn = typeof root === "string" ? root.trim() : root.urn.trim();
            if (!rootUrn) {
                throw new Error("graphLayering: root urn must be a non-empty string");
            }
            if (seen.has(rootUrn)) {
                continue;
            }
            seen.add(rootUrn);
            try {
                layering[rootUrn] = await this.graphNeighborhood(rootUrn, limit);
            }
            catch (error) {
                if (error instanceof APIError) {
                    layering[rootUrn] = {
                        root_urn: rootUrn,
                        error: error.message,
                    };
                    continue;
                }
                throw error;
            }
        }
        return layering;
    }
    graphSummary(layering) {
        return summarizeGraphLayering(layering);
    }
    ref(kind, externalId, label = "") {
        const normalizedKind = kind.trim();
        const normalizedExternalId = externalId.trim();
        if (!normalizedKind) {
            throw new Error("kind is required");
        }
        if (!normalizedExternalId) {
            throw new Error("externalId is required");
        }
        return {
            urn: this.buildURN(normalizedKind, normalizedExternalId),
            entity_type: normalizedKind,
            label: label.trim() || normalizedExternalId,
        };
    }
    exists(subject, options = {}) {
        return this.buildClaim(subject, "exists", {
            ...options,
            claim_type: options.claim_type ?? "existence",
        });
    }
    attr(subject, predicate, value, options = {}) {
        return this.buildClaim(subject, predicate, {
            ...options,
            claim_type: options.claim_type ?? "attribute",
            object_value: value.trim(),
        });
    }
    rel(subject, predicate, object, options = {}) {
        return this.buildClaim(subject, predicate, {
            ...options,
            claim_type: options.claim_type ?? "relation",
            object_ref: object,
            object_urn: object.urn,
        });
    }
    buildClaim(subject, predicate, options) {
        const normalizedPredicate = predicate.trim();
        if (!subject.urn.trim()) {
            throw new Error("subject.urn is required");
        }
        if (!normalizedPredicate) {
            throw new Error("predicate is required");
        }
        return {
            id: options.id,
            subject_urn: subject.urn.trim(),
            subject_ref: subject,
            predicate: normalizedPredicate,
            object_ref: options.object_ref,
            object_urn: options.object_urn?.trim(),
            object_value: options.object_value?.trim(),
            claim_type: options.claim_type,
            status: options.status,
            source_event_id: options.source_event_id,
            observed_at: options.observed_at,
            valid_from: options.valid_from,
            valid_to: options.valid_to,
            attributes: options.attributes,
        };
    }
    buildURN(kind, externalId) {
        return ["urn", "cerebro", this.tenantId, "runtime", this.runtimeId, kind, externalId].join(":");
    }
}
export function summarizeGraphLayering(layering) {
    const roots = [];
    const nodeCounts = new Map();
    const relationCounts = new Map();
    const neighborhoodSizes = {};
    const errors = {};
    const seenNodes = new Set();
    const seenRelations = new Set();
    for (const [rootUrn, entry] of Object.entries(layering)) {
        if ("error" in entry) {
            errors[entry.root_urn || rootUrn] = entry.error;
            continue;
        }
        const root = entry.root;
        if (!root?.urn) {
            continue;
        }
        roots.push(root);
        neighborhoodSizes[root.urn] = {
            neighbors: entry.neighbors?.length ?? 0,
            relations: entry.relations?.length ?? 0,
        };
        for (const node of [root, ...(entry.neighbors ?? [])]) {
            if (!node?.urn || seenNodes.has(node.urn)) {
                continue;
            }
            seenNodes.add(node.urn);
            const entityType = node.entity_type || "unknown";
            nodeCounts.set(entityType, (nodeCounts.get(entityType) ?? 0) + 1);
        }
        for (const relation of entry.relations ?? []) {
            if (!relation?.from_urn || !relation?.relation || !relation?.to_urn) {
                continue;
            }
            const key = `${relation.from_urn}\u0000${relation.relation}\u0000${relation.to_urn}`;
            if (seenRelations.has(key)) {
                continue;
            }
            seenRelations.add(key);
            relationCounts.set(relation.relation, (relationCounts.get(relation.relation) ?? 0) + 1);
        }
    }
    return {
        roots,
        node_counts_by_type: Object.fromEntries(nodeCounts),
        relation_counts_by_type: Object.fromEntries(relationCounts),
        neighborhood_sizes: neighborhoodSizes,
        errors,
    };
}
