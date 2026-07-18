import type { AgentTool } from "@earendil-works/pi-agent-core";
import { createHash } from "node:crypto";
import { z } from "zod";
import { securityAgentToolMetadata, type SecurityToolAuthority, type SecurityToolFamily } from "./tools/tool-metadata.js";

const toolArgumentsSchema = z.record(z.string().min(1).max(160), z.unknown());

export interface AgentToolCatalogEntry {
  name: string;
  label: string;
  description: string;
  family: SecurityToolFamily;
  authority: SecurityToolAuthority;
  sideEffect: string;
  retry: string;
  credentialScope: string;
  requiredArguments: string[];
  optionalArguments: string[];
}

export interface AgentToolCatalogQuery {
  query?: string;
  families?: SecurityToolFamily[];
  authorities?: SecurityToolAuthority[];
  limit?: number;
}

export interface AgentToolCatalogSignature extends AgentToolCatalogEntry {
  signature: string;
}

export interface ToolArgumentValidation {
  valid: boolean;
  arguments?: Record<string, unknown>;
  errors: string[];
}

export class AgentToolCatalog {
  private readonly tools = new Map<string, AgentTool>();
  private readonly entries = new Map<string, AgentToolCatalogEntry>();

  constructor(tools: AgentTool[]) {
    for (const tool of tools) {
      if (this.tools.has(tool.name)) throw new Error(`Duplicate agent tool ${tool.name}.`);
      this.tools.set(tool.name, tool);
      this.entries.set(tool.name, catalogEntry(tool));
    }
  }

  get(name: string): AgentTool | undefined {
    return this.tools.get(name);
  }

  entry(name: string): AgentToolCatalogEntry | undefined {
    const entry = this.entries.get(name);
    return entry ? cloneEntry(entry) : undefined;
  }

  list(): AgentToolCatalogEntry[] {
    return [...this.entries.values()].map(cloneEntry).sort((left, right) => left.name.localeCompare(right.name));
  }

  search(input: AgentToolCatalogQuery): AgentToolCatalogEntry[] {
    const terms = searchTerms(input.query ?? "");
    const families = input.families?.length ? new Set(input.families) : undefined;
    const authorities = input.authorities?.length ? new Set(input.authorities) : undefined;
    const limit = Math.max(1, Math.min(20, Math.floor(input.limit ?? 8)));
    return [...this.entries.values()]
      .filter((entry) => !families || families.has(entry.family))
      .filter((entry) => !authorities || authorities.has(entry.authority))
      .map((entry) => ({ entry, score: catalogScore(entry, terms) }))
      .filter((item) => terms.length === 0 || item.score > 0)
      .sort((left, right) => right.score - left.score || left.entry.name.localeCompare(right.entry.name))
      .slice(0, limit)
      .map((item) => cloneEntry(item.entry));
  }

  signature(name: string): AgentToolCatalogSignature | undefined {
    const tool = this.tools.get(name);
    const entry = this.entries.get(name);
    return tool && entry ? signatureEntry(tool, entry) : undefined;
  }

  signatures(names: Iterable<string>): AgentToolCatalogSignature[] {
    return [...new Set(names)]
      .sort((left, right) => left.localeCompare(right))
      .map((name) => this.signature(name))
      .filter((entry): entry is AgentToolCatalogSignature => Boolean(entry));
  }

  searchSignatures(input: AgentToolCatalogQuery): AgentToolCatalogSignature[] {
    return this.search(input)
      .map((entry) => this.signature(entry.name))
      .filter((entry): entry is AgentToolCatalogSignature => Boolean(entry));
  }

  digest(names: Iterable<string>): string {
    const signatures = this.signatures(names);
    return `sha256:${createHash("sha256").update(canonicalJson(signatures)).digest("hex")}`;
  }

  validateArguments(name: string, value: unknown): ToolArgumentValidation {
    const parsed = toolArgumentsSchema.safeParse(value);
    if (!parsed.success) return { valid: false, errors: ["Tool arguments must be a JSON object."] };
    const serialized = JSON.stringify(parsed.data);
    if (serialized.length > 20_000) return { valid: false, errors: ["Tool arguments exceed 20000 characters."] };
    const tool = this.tools.get(name);
    if (!tool) return { valid: false, errors: [`Unknown agent tool ${name}.`] };
    const shape = parameterShape(tool.parameters);
    const errors = [
      ...shape.required.filter((field) => !(field in parsed.data)).map((field) => `Missing required argument ${field}.`),
      ...Object.keys(parsed.data).filter((field) => shape.known.size > 0 && !shape.known.has(field)).map((field) => `Unknown argument ${field}.`),
      ...Object.entries(parsed.data).flatMap(([field, item]) => {
        const schema = shape.properties[field];
        return schema && !matchesTopLevelSchema(item, schema) ? [`Argument ${field} has the wrong type.`] : [];
      }),
    ];
    return errors.length > 0 ? { valid: false, errors } : { valid: true, arguments: parsed.data, errors: [] };
  }
}

function signatureEntry(tool: AgentTool, entry: AgentToolCatalogEntry): AgentToolCatalogSignature {
  const shape = parameterShape(tool.parameters);
  const fields = [...shape.known]
    .sort((left, right) => left.localeCompare(right))
    .map((field) => `${field}${shape.required.includes(field) ? "" : "?"}: ${typescriptType(shape.properties[field] ?? {})}`);
  return {
    ...cloneEntry(entry),
    signature: `${tool.name}(args: { ${fields.join("; ")} }): Promise<ToolResult>`,
  };
}

function catalogEntry(tool: AgentTool): AgentToolCatalogEntry {
  const metadata = securityAgentToolMetadata(tool.name);
  const shape = parameterShape(tool.parameters);
  return {
    name: tool.name,
    label: tool.label,
    description: tool.description,
    family: metadata.family,
    authority: metadata.authority,
    sideEffect: metadata.sideEffect,
    retry: metadata.retry,
    credentialScope: metadata.credentialScope,
    requiredArguments: [...shape.required],
    optionalArguments: [...shape.known].filter((field) => !shape.required.includes(field)),
  };
}

function catalogScore(entry: AgentToolCatalogEntry, terms: string[]): number {
  if (terms.length === 0) return 1;
  const name = normalize(entry.name);
  const label = normalize(entry.label);
  const description = normalize(entry.description);
  const family = normalize(entry.family);
  return terms.reduce((score, term) => score
    + (name === term ? 20 : name.includes(term) ? 8 : 0)
    + (label.includes(term) ? 5 : 0)
    + (family.includes(term) ? 4 : 0)
    + (description.includes(term) ? 2 : 0), 0);
}

function searchTerms(value: string): string[] {
  return [...new Set(normalize(value).split(" ").filter((term) => term.length > 1))].slice(0, 16);
}

function normalize(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

function cloneEntry(entry: AgentToolCatalogEntry): AgentToolCatalogEntry {
  return { ...entry, requiredArguments: [...entry.requiredArguments], optionalArguments: [...entry.optionalArguments] };
}

function parameterShape(value: unknown): {
  known: Set<string>;
  required: string[];
  properties: Record<string, Record<string, unknown>>;
} {
  const record = objectValue(value);
  const properties = objectValue(record?.properties) ?? {};
  const required = Array.isArray(record?.required) ? record.required.map(String) : [];
  return {
    known: new Set(Object.keys(properties)),
    required,
    properties: Object.fromEntries(Object.entries(properties).map(([key, item]) => [key, objectValue(item) ?? {}])),
  };
}

function matchesTopLevelSchema(value: unknown, schema: Record<string, unknown>): boolean {
  if (Array.isArray(schema.anyOf)) return schema.anyOf.some((candidate) => matchesTopLevelSchema(value, objectValue(candidate) ?? {}));
  if (Array.isArray(schema.oneOf)) return schema.oneOf.some((candidate) => matchesTopLevelSchema(value, objectValue(candidate) ?? {}));
  if ("const" in schema && value !== schema.const) return false;
  if (Array.isArray(schema.enum) && !schema.enum.some((candidate) => candidate === value)) return false;
  if (schema.type === "string") {
    return typeof value === "string"
      && (typeof schema.minLength !== "number" || value.length >= schema.minLength)
      && (typeof schema.maxLength !== "number" || value.length <= schema.maxLength);
  }
  if (schema.type === "number" || schema.type === "integer") {
    return typeof value === "number"
      && Number.isFinite(value)
      && (schema.type !== "integer" || Number.isInteger(value))
      && (typeof schema.minimum !== "number" || value >= schema.minimum)
      && (typeof schema.maximum !== "number" || value <= schema.maximum);
  }
  if (schema.type === "boolean") return typeof value === "boolean";
  if (schema.type === "array") {
    if (!Array.isArray(value)) return false;
    if (typeof schema.minItems === "number" && value.length < schema.minItems) return false;
    if (typeof schema.maxItems === "number" && value.length > schema.maxItems) return false;
    const itemSchema = objectValue(schema.items);
    return !itemSchema || value.every((item) => matchesTopLevelSchema(item, itemSchema));
  }
  if (schema.type === "object") {
    const record = objectValue(value);
    if (!record) return false;
    const properties = objectValue(schema.properties) ?? {};
    const required = Array.isArray(schema.required) ? schema.required.map(String) : [];
    if (required.some((field) => !(field in record))) return false;
    return Object.entries(record).every(([field, item]) => {
      const property = objectValue(properties[field]);
      return property ? matchesTopLevelSchema(item, property) : schema.additionalProperties !== false;
    });
  }
  return true;
}

function typescriptType(schema: Record<string, unknown>, depth = 0): string {
  if (depth >= 3) return "unknown";
  if (Array.isArray(schema.anyOf)) return unionType(schema.anyOf, depth);
  if (Array.isArray(schema.oneOf)) return unionType(schema.oneOf, depth);
  if ("const" in schema) return JSON.stringify(schema.const);
  if (Array.isArray(schema.enum)) return schema.enum.map((item) => JSON.stringify(item)).join(" | ") || "unknown";
  if (schema.type === "string") return "string";
  if (schema.type === "number" || schema.type === "integer") return "number";
  if (schema.type === "boolean") return "boolean";
  if (schema.type === "array") return `Array<${typescriptType(objectValue(schema.items) ?? {}, depth + 1)}>`;
  if (schema.type === "object") {
    const nested = parameterShape(schema);
    const fields = [...nested.known]
      .sort((left, right) => left.localeCompare(right))
      .map((field) => `${field}${nested.required.includes(field) ? "" : "?"}: ${typescriptType(nested.properties[field] ?? {}, depth + 1)}`);
    return `{ ${fields.join("; ")} }`;
  }
  return "unknown";
}

function unionType(candidates: unknown[], depth: number): string {
  const types = candidates.map((candidate) => typescriptType(objectValue(candidate) ?? {}, depth + 1));
  return [...new Set(types)].join(" | ") || "unknown";
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = objectValue(value);
  if (record) {
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}
