"use client";

import { useMemo, useState } from "react";

import { buildApiUrl, normalizePath } from "@/lib/api";
import type {
  OpenApiOperation,
  OpenApiParameter,
  OpenApiSchema,
} from "@/lib/openapi";
import { useApiKey } from "@/components/providers";

type EndpointResult = {
  status: number;
  body: string;
  contentType: string | null;
};

const buildPath = (path: string, params: Record<string, string>) =>
  path
    .replace(/{([A-Za-z0-9_]+)}/g, (_match, key) =>
      encodeURIComponent(params[key] ?? ""),
    )
    .replace(/:([A-Za-z0-9_]+)/g, (_match, key) =>
      encodeURIComponent(params[key] ?? ""),
    );

const getSchemaName = (ref?: string) => ref?.split("/").pop();

const resolveSchema = (
  schema: OpenApiSchema | undefined,
  schemas: Record<string, OpenApiSchema>,
  seen = new Set<string>(),
): OpenApiSchema | undefined => {
  if (!schema) {
    return undefined;
  }
  if (!schema.$ref) {
    return schema;
  }
  const name = getSchemaName(schema.$ref);
  if (!name || seen.has(name)) {
    return schema;
  }
  seen.add(name);
  const resolved = schemas[name];
  return resolved ? { ...resolved, title: name } : schema;
};

function SchemaView({
  schema,
  schemas,
  depth = 0,
  seen,
}: {
  schema?: OpenApiSchema;
  schemas: Record<string, OpenApiSchema>;
  depth?: number;
  seen?: Set<string>;
}) {
  const localSeen = seen ?? new Set<string>();
  const resolved = resolveSchema(schema, schemas, localSeen);
  if (!resolved) {
    return <div className="text-xs text-neutral-500">Schema unavailable</div>;
  }

  const label = resolved.title ?? resolved.type ?? (resolved.$ref ? "ref" : "");
  const padding = { paddingLeft: `${depth * 12}px` };

  if (resolved.oneOf || resolved.anyOf || resolved.allOf) {
    const variants = resolved.oneOf ?? resolved.anyOf ?? resolved.allOf ?? [];
    return (
      <div className="space-y-2" style={padding}>
        <div className="text-xs font-semibold uppercase tracking-wide text-neutral-500">
          {resolved.oneOf ? "One of" : resolved.anyOf ? "Any of" : "All of"}
        </div>
        {variants.map((variant, index) => (
          <SchemaView
            key={index}
            schema={variant}
            schemas={schemas}
            depth={depth + 1}
            seen={localSeen}
          />
        ))}
      </div>
    );
  }

  if (resolved.type === "object" || resolved.properties) {
    const properties = resolved.properties ?? {};
    return (
      <div className="space-y-2" style={padding}>
        <div className="text-xs font-semibold uppercase tracking-wide text-neutral-500">
          {label || "Object"}
        </div>
        <div className="space-y-1">
          {Object.entries(properties).map(([key, value]) => (
            <div key={key} className="text-xs text-neutral-600">
              <span className="font-semibold text-neutral-700">{key}</span>
              <span className="mx-2 text-neutral-400">•</span>
              <SchemaView
                schema={value}
                schemas={schemas}
                depth={depth + 1}
                seen={localSeen}
              />
            </div>
          ))}
          {resolved.additionalProperties && (
            <div className="text-xs text-neutral-600">
              additionalProperties
              <span className="mx-2 text-neutral-400">•</span>
              <SchemaView
                schema={
                  resolved.additionalProperties === true
                    ? { type: "object" }
                    : resolved.additionalProperties
                }
                schemas={schemas}
                depth={depth + 1}
                seen={localSeen}
              />
            </div>
          )}
        </div>
      </div>
    );
  }

  if (resolved.type === "array") {
    return (
      <div className="space-y-1" style={padding}>
        <div className="text-xs font-semibold uppercase tracking-wide text-neutral-500">
          Array
        </div>
        <SchemaView
          schema={resolved.items}
          schemas={schemas}
          depth={depth + 1}
          seen={localSeen}
        />
      </div>
    );
  }

  return (
    <div className="text-xs text-neutral-600" style={padding}>
      {label || "Unknown"}
      {resolved.enum && (
        <span className="ml-2 text-neutral-500">[{resolved.enum.join(", ")}]</span>
      )}
    </div>
  );
}

const buildParamLabel = (param: OpenApiParameter) => {
  const type = param.schema?.type ?? "string";
  const required = param.required ? "required" : "optional";
  const location = param.in ?? "query";
  return `${param.name} • ${type} • ${location} • ${required}`;
};

function EndpointCard({
  operation,
  schemas,
}: {
  operation: OpenApiOperation;
  schemas: Record<string, OpenApiSchema>;
}) {
  const { apiKey } = useApiKey();
  const parameters = useMemo(
    () =>
      [...(operation.parameters ?? [])].sort((a, b) => {
        if (a.in === b.in) {
          if (a.required === b.required) {
            return a.name.localeCompare(b.name);
          }
          return a.required ? -1 : 1;
        }
        if (a.in === "path") {
          return -1;
        }
        if (b.in === "path") {
          return 1;
        }
        return a.in.localeCompare(b.in);
      }),
    [operation.parameters],
  );
  const defaults = useMemo(
    () =>
      Object.fromEntries(
        parameters.map((param) => [param.name, String(param.schema?.default ?? "")]),
      ),
    [parameters],
  );
  const [values, setValues] = useState<Record<string, string>>(defaults);
  const [result, setResult] = useState<EndpointResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const requiredParams = parameters.filter((param) => param.required);
  const missingParams = requiredParams.filter((param) => !values[param.name]);
  const filledPath = buildPath(operation.path, values);
  const normalizedPath = normalizePath(filledPath);
  const queryParams = parameters.filter((param) => param.in === "query");
  const queryString = new URLSearchParams(
    queryParams
      .filter((param) => values[param.name])
      .map((param) => [param.name, values[param.name]]),
  ).toString();
  const fullPath = queryString ? `${normalizedPath}?${queryString}` : normalizedPath;
  const proxyUrl = `/api/cerebro${fullPath}`;
  const externalUrl = buildApiUrl(fullPath);

  const handleFetch = async () => {
    if (missingParams.length > 0) {
      setError(`Missing: ${missingParams.map((param) => param.name).join(", ")}`);
      return;
    }

    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch(proxyUrl, {
        method: "GET",
        headers: apiKey ? { "X-API-Key": apiKey } : {},
        cache: "no-store",
      });

      const body = await response.text();
      setResult({
        status: response.status,
        body,
        contentType: response.headers.get("content-type"),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setIsLoading(false);
    }
  };

  const renderedBody = useMemo(() => {
    if (!result) {
      return null;
    }
    if (operation.responseHint === "text") {
      return result.body;
    }
    try {
      return JSON.stringify(JSON.parse(result.body), null, 2);
    } catch {
      return result.body;
    }
  }, [operation.responseHint, result]);

  return (
    <div className="rounded-lg border border-stone-200 bg-white p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2 text-sm font-semibold text-neutral-950">
            <span>{operation.summary ?? operation.path}</span>
            {operation.source === "manual" && (
              <span className="rounded-full bg-violet-50 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-neutral-700">
                Manual
              </span>
            )}
          </div>
          <div className="text-xs text-neutral-500">
            {operation.method} {operation.path}
          </div>
          {operation.description && (
            <div className="mt-1 text-xs text-neutral-500">
              {operation.description}
            </div>
          )}
        </div>
        <div className="flex items-center gap-2">
          <a
            href={missingParams.length === 0 ? externalUrl : undefined}
            target="_blank"
            rel="noreferrer"
            className={`rounded-md border border-stone-300 px-3 py-2 text-xs font-semibold uppercase tracking-wide transition ${
              missingParams.length === 0
                ? "text-neutral-700 hover:border-stone-300 hover:text-neutral-950"
                : "cursor-not-allowed text-neutral-400"
            }`}
          >
            Open
          </a>
          <button
            type="button"
            onClick={handleFetch}
            disabled={isLoading}
            className="rounded-md bg-neutral-950 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-white transition hover:bg-white disabled:cursor-not-allowed disabled:bg-neutral-300 disabled:text-neutral-700"
          >
            {isLoading ? "Loading" : "Fetch"}
          </button>
        </div>
      </div>

      {parameters.length > 0 && (
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          {parameters.map((param) => (
            <label key={`${param.in}-${param.name}`} className="text-xs text-neutral-600">
              {buildParamLabel(param)}
              <input
                value={values[param.name]}
                onChange={(event) =>
                  setValues((current) => ({
                    ...current,
                    [param.name]: event.target.value,
                  }))
                }
                className="mt-1 w-full rounded-md border border-stone-200 bg-neutral-50 px-3 py-2 text-sm text-neutral-950 placeholder:text-neutral-500"
                placeholder={`Enter ${param.name}`}
              />
            </label>
          ))}
        </div>
      )}

      {operation.response?.schema && (
        <div className="mt-4 rounded-lg border border-stone-200 bg-neutral-50 p-3">
          <div className="text-xs font-semibold uppercase tracking-wide text-neutral-600">
            Response schema
          </div>
          <div className="mt-2">
            <SchemaView schema={operation.response.schema} schemas={schemas} />
          </div>
        </div>
      )}

      {error && <div className="mt-3 text-xs text-rose-700">{error}</div>}

      {result && (
        <div className="mt-3 space-y-2">
          <div className="flex items-center gap-2 text-xs text-neutral-500">
            <span>Status</span>
            <span className="rounded-full bg-violet-50 px-2 py-1 text-neutral-800">
              {result.status}
            </span>
            {result.contentType && (
              <span className="rounded-full bg-violet-50 px-2 py-1 text-neutral-800">
                {result.contentType}
              </span>
            )}
          </div>
          <pre className="max-h-96 overflow-auto rounded-lg border border-stone-200 bg-neutral-50 p-3 text-xs text-neutral-800">
            {renderedBody}
          </pre>
        </div>
      )}
    </div>
  );
}

export default function ResourceExplorer({
  operations,
  schemas,
}: {
  operations: OpenApiOperation[];
  schemas: Record<string, OpenApiSchema>;
}) {
  if (operations.length === 0) {
    return (
      <div className="rounded-lg border border-stone-200 bg-white p-6 text-sm text-neutral-600">
        No read-only endpoints are available for this resource.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {operations.map((operation) => (
        <EndpointCard
          key={operation.id}
          operation={operation}
          schemas={schemas}
        />
      ))}
    </div>
  );
}
