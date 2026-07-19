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
        return this.requestJson("GET", `/platform/graph/neighborhood?${query.toString()}`);
    }
    async listComplianceWorkItems(options = {}) {
        const query = new URLSearchParams();
        if (options.tenantId)
            query.set("tenant_id", options.tenantId);
        if (options.state)
            query.set("state", options.state);
        if (options.ownerId)
            query.set("owner_id", options.ownerId);
        if (options.cursor)
            query.set("cursor", options.cursor);
        if (options.limit !== undefined)
            query.set("limit", String(options.limit));
        const suffix = query.toString() ? `?${query.toString()}` : "";
        return this.requestJson("GET", `/grc/work-items${suffix}`);
    }
    async getComplianceWorkItem(workItemId, tenantId = "") {
        const normalizedID = workItemId.trim();
        if (!normalizedID)
            throw new Error("workItemId is required");
        const query = new URLSearchParams();
        if (tenantId)
            query.set("tenant_id", tenantId);
        const suffix = query.toString() ? `?${query.toString()}` : "";
        return this.requestJson("GET", `/grc/work-items/${encodeURIComponent(normalizedID)}${suffix}`);
    }
    async commandComplianceWorkItem(workItemId, command, tenantId = "") {
        const normalizedID = workItemId.trim();
        if (!normalizedID)
            throw new Error("workItemId is required");
        const query = new URLSearchParams();
        if (tenantId)
            query.set("tenant_id", tenantId);
        const suffix = query.toString() ? `?${query.toString()}` : "";
        return this.requestJson("POST", `/grc/work-items/${encodeURIComponent(normalizedID)}/commands${suffix}`, command);
    }
    async createJob(request, idempotencyKey = "") {
        const headers = {};
        if (idempotencyKey) {
            headers["Idempotency-Key"] = idempotencyKey;
        }
        return this.requestJson("POST", "/platform/jobs", request, headers);
    }
    async listJobs(options = {}) {
        const query = new URLSearchParams();
        for (const [key, value] of Object.entries(options)) {
            if (value === undefined || value === null || value === "") {
                continue;
            }
            query.set(key, String(value));
        }
        const suffix = query.toString() ? `?${query.toString()}` : "";
        return this.requestJson("GET", `/platform/jobs${suffix}`);
    }
    async getJob(jobId) {
        return this.requestJson("GET", `/platform/jobs/${encodeURIComponent(jobId)}`);
    }
    async listJobEvents(jobId, limit = 0) {
        const suffix = limit > 0 ? `?limit=${encodeURIComponent(String(limit))}` : "";
        return this.requestJson("GET", `/platform/jobs/${encodeURIComponent(jobId)}/events${suffix}`);
    }
    async cancelJob(jobId) {
        return this.requestJson("POST", `/platform/jobs/${encodeURIComponent(jobId)}/cancel`);
    }
    integration(options) {
        return new IntegrationClient(this, options);
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
