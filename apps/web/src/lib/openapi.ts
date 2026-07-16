import type { ManualOperation } from "@/lib/resources";
import { manualOperations, manualTags } from "@/lib/resources";

export type OpenApiTag = {
  name: string;
  description?: string;
};

export type OpenApiSchema = {
  type?: string;
  format?: string;
  title?: string;
  description?: string;
  enum?: string[];
  default?: unknown;
  properties?: Record<string, OpenApiSchema>;
  items?: OpenApiSchema;
  additionalProperties?: boolean | OpenApiSchema;
  required?: string[];
  oneOf?: OpenApiSchema[];
  anyOf?: OpenApiSchema[];
  allOf?: OpenApiSchema[];
  $ref?: string;
};

export type OpenApiParameter = {
  name: string;
  in: "path" | "query" | string;
  required?: boolean;
  description?: string;
  schema?: OpenApiSchema;
  example?: unknown;
};

export type OpenApiResponse = {
  status: string;
  description?: string;
  contentType?: string;
  schema?: OpenApiSchema;
};

export type OpenApiOperation = {
  id: string;
  tag: string;
  method: string;
  path: string;
  summary?: string;
  description?: string;
  parameters: OpenApiParameter[];
  response?: OpenApiResponse;
  source: "openapi" | "manual";
  responseHint?: "json" | "text";
};

export type OpenApiModel = {
  info?: { title?: string; version?: string; description?: string };
  tags: OpenApiTag[];
  operations: OpenApiOperation[];
  schemas: Record<string, OpenApiSchema>;
};

type OpenApiRef = { $ref: string };

type OpenApiResponseObject = {
  description?: string;
  content?: Record<string, { schema?: OpenApiSchema }>;
};

type OpenApiOperationObject = {
  operationId?: string;
  tags?: string[];
  summary?: string;
  description?: string;
  parameters?: Array<OpenApiParameter | OpenApiRef>;
  responses?: Record<string, OpenApiResponseObject>;
};

type OpenApiPathItem = {
  parameters?: Array<OpenApiParameter | OpenApiRef>;
  [method: string]:
    | OpenApiOperationObject
    | Array<OpenApiParameter | OpenApiRef>
    | undefined;
};

type OpenApiSpec = {
  info?: OpenApiModel["info"];
  tags?: OpenApiTag[];
  paths?: Record<string, OpenApiPathItem>;
  components?: {
    schemas?: Record<string, OpenApiSchema>;
    parameters?: Record<string, OpenApiParameter>;
  };
};

const resolveRef = (spec: OpenApiSpec, ref?: string) => {
  if (!ref) {
    return undefined;
  }
  const path = ref.replace(/^#\//, "").split("/");
  let current: unknown = spec as unknown;
  for (const key of path) {
    if (!current || typeof current !== "object") {
      return undefined;
    }
    current = (current as Record<string, unknown>)[key];
  }
  return current;
};

const resolveParameter = (
  spec: OpenApiSpec,
  parameter: OpenApiParameter | OpenApiRef,
) => {
  if ("$ref" in parameter && parameter.$ref) {
    const resolved = resolveRef(spec, parameter.$ref);
    return resolved as OpenApiParameter | undefined;
  }
  return parameter;
};

const mergeParameters = (
  pathParams: OpenApiParameter[] = [],
  opParams: OpenApiParameter[] = [],
) => {
  const map = new Map<string, OpenApiParameter>();
  [...pathParams, ...opParams].forEach((param) => {
    if (!param) {
      return;
    }
    map.set(`${param.in}:${param.name}`, param);
  });
  return Array.from(map.values());
};

const pickResponse = (
  responses: Record<string, OpenApiResponseObject> | undefined,
) => {
  if (!responses) {
    return undefined;
  }
  const status =
    responses["200"]
      ? "200"
      : responses["201"]
        ? "201"
        : Object.keys(responses)[0];
  if (!status) {
    return undefined;
  }
  const response = responses[status];
  const content = response?.content ?? {};
  const contentType =
    content["application/json"]
      ? "application/json"
      : Object.keys(content)[0];
  const schema = contentType ? content?.[contentType]?.schema : undefined;
  return {
    status,
    description: response?.description,
    contentType,
    schema,
  } as OpenApiResponse;
};

const inferOperationTag = (path: string, tag?: string) => {
  if (tag && tag !== "Uncategorized") {
    return tag;
  }
  if (path === "/health" || path === "/healthz" || path === "/openapi.yaml") {
    return "System";
  }
  if (path.startsWith("/sources")) {
    return "Sources";
  }
  if (path.startsWith("/connectors")) {
    return "Connectors";
  }
  if (path.startsWith("/source-runtimes")) {
    return "Source Runtimes";
  }
  if (
    path.startsWith("/finding-rules") ||
    path.startsWith("/findings") ||
    path.startsWith("/finding-evaluation-runs") ||
    path.startsWith("/finding-evidence")
  ) {
    return "Findings";
  }
  if (path.startsWith("/grc")) {
    return "GRC";
  }
  if (path.startsWith("/reports") || path.startsWith("/report-runs")) {
    return "Reports";
  }
  if (path.startsWith("/graph") || path.startsWith("/platform/graph")) {
    return "Graph";
  }
  if (path.startsWith("/platform/knowledge") || path.startsWith("/platform/workflow")) {
    return "Platform";
  }
  return tag ?? "Uncategorized";
};

const buildOperations = (spec: OpenApiSpec) => {
  const operations: OpenApiOperation[] = [];
  const paths = spec.paths ?? {};
  Object.entries(paths).forEach(([path, methods]) => {
    const pathParameters = (methods.parameters ?? [])
      .map((param) => resolveParameter(spec, param))
      .filter(Boolean) as OpenApiParameter[];

    Object.entries(methods).forEach(([method, operation]) => {
      if (method === "parameters") {
        return;
      }
      if (method.toLowerCase() !== "get") {
        return;
      }
      if (!operation || typeof operation !== "object" || Array.isArray(operation)) {
        return;
      }
      const op = operation as OpenApiOperationObject;
      const opParameters = (op.parameters ?? [])
        .map((param) => resolveParameter(spec, param))
        .filter(Boolean) as OpenApiParameter[];
      const parameters = mergeParameters(pathParameters, opParameters);
      const tag = inferOperationTag(path, op.tags?.[0]);
      const response = pickResponse(op.responses);
      const responseHint = response?.contentType?.includes("json")
        ? undefined
        : response?.contentType
          ? "text"
          : undefined;
      operations.push({
        id: op.operationId ?? `${method}:${path}`,
        tag,
        method: method.toUpperCase(),
        path,
        summary: op.summary,
        description: op.description,
        parameters,
        response,
        responseHint,
        source: "openapi",
      });
    });
  });
  return operations;
};

const buildManualOperations = (
  manual: ManualOperation[],
  existing: OpenApiOperation[],
): OpenApiOperation[] => {
  const existingKeys = new Set(
    existing.map((op) => `${op.method}:${op.path}`),
  );
  return manual
    .map((op) => ({
      id: `manual:${op.path}`,
      tag: op.tag,
      method: "GET",
      path: op.path.replace(/:([a-zA-Z0-9_]+)/g, "{$1}"),
      summary: op.summary,
      description: op.description,
      parameters: (op.params ?? []).map((param) => ({
        name: param,
        in: "path" as const,
        required: true,
      })),
      response: op.response
        ? { status: "200", contentType: op.response === "text" ? "text/plain" : "application/json" }
        : undefined,
      responseHint: op.response,
      source: "manual" as const,
    }))
    .filter((op) => !existingKeys.has(`${op.method}:${op.path}`));
};

export const tagSlug = (name: string) =>
  name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");

export const buildOpenApiModel = (spec: OpenApiSpec): OpenApiModel => {
  const openApiOperations = buildOperations(spec);
  const manualOps = buildManualOperations(manualOperations, openApiOperations);
  const tags = [...(spec.tags ?? [])];
  const tagNames = new Set(tags.map((tag) => tag.name));

  const operationTagNames = new Set(
    [...openApiOperations, ...manualOps].map((operation) => operation.tag),
  );

  Object.entries(manualTags).forEach(([name, description]) => {
    if (!tagNames.has(name)) {
      tags.push({ name, description });
      tagNames.add(name);
    }
  });

  operationTagNames.forEach((name) => {
    if (!tagNames.has(name)) {
      tags.push({ name, description: manualTags[name] });
      tagNames.add(name);
    }
  });

  return {
    info: spec.info,
    tags: tags.sort((a, b) => a.name.localeCompare(b.name)),
    operations: [...openApiOperations, ...manualOps].sort((a, b) => {
      if (a.tag === b.tag) {
        return a.path.localeCompare(b.path);
      }
      return a.tag.localeCompare(b.tag);
    }),
    schemas: spec.components?.schemas ?? {},
  };
};
