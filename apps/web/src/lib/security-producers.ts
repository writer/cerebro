export type SecurityProducer = {
  id: string;
  label: string;
  description?: string;
  repo: string;
  runtimeIds: string[];
  sourceIds: string[];
  mcpTools: string[];
  resourceTemplates: string[];
  contextKeys: string[];
  responseActions: SecurityProducerResponseAction[];
};

export type SecurityProducerResponseAction = {
  id: string;
  label: string;
  providers: string[];
  targetTypes: string[];
  requiredContextKeys: string[];
  mode: string;
  mcpTool?: string;
  runtimeAction?: string;
  externalOwner?: string;
  dryRun: boolean;
  requiresApproval: boolean;
};

export type SecurityProducerCatalog =
  | { state: "ready"; producers: SecurityProducer[] }
  | { state: "invalid" };

const hasOwn = (record: Record<string, unknown>, key: string) =>
  Object.prototype.hasOwnProperty.call(record, key);

const stringField = (
  record: Record<string, unknown>,
  key: string,
): string | null => {
  if (!hasOwn(record, key)) return "";
  const value = record[key];
  return typeof value === "string" ? value.trim() : null;
};

const stringListField = (
  record: Record<string, unknown>,
  key: string,
): string[] | null => {
  if (!hasOwn(record, key)) return [];
  const value = record[key];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !item.trim())) {
    return null;
  }
  return value.map((item) => item.trim());
};

const boolField = (
  record: Record<string, unknown>,
  key: string,
  fallback: boolean,
): boolean | null => {
  if (!hasOwn(record, key)) return fallback;
  return typeof record[key] === "boolean" ? record[key] : null;
};

const responseActionFromRecord = (value: unknown): SecurityProducerResponseAction | null => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const id = stringField(record, "id");
  const label = stringField(record, "label");
  if (!id || !label) return null;
  const providers = stringListField(record, "providers");
  const targetTypes = stringListField(record, "targetTypes");
  const requiredContextKeys = stringListField(record, "requiredContextKeys");
  const mode = stringField(record, "mode");
  const mcpTool = stringField(record, "mcpTool");
  const runtimeAction = stringField(record, "runtimeAction");
  const externalOwner = stringField(record, "externalOwner");
  const dryRun = boolField(record, "dryRun", true);
  const requiresApproval = boolField(record, "requiresApproval", true);
  if (
    !providers || !targetTypes || !requiredContextKeys || mode === null ||
    mcpTool === null || runtimeAction === null || externalOwner === null ||
    dryRun === null || requiresApproval === null
  ) return null;
  return {
    id,
    label,
    providers,
    targetTypes,
    requiredContextKeys,
    mode: mode || "external_workflow",
    mcpTool: mcpTool || undefined,
    runtimeAction: runtimeAction || undefined,
    externalOwner: externalOwner || undefined,
    dryRun,
    requiresApproval,
  };
};

const responseActionList = (
  record: Record<string, unknown>,
): SecurityProducerResponseAction[] | null => {
  if (!hasOwn(record, "responseActions")) return [];
  const value = record.responseActions;
  if (!Array.isArray(value)) return null;
  const actions: SecurityProducerResponseAction[] = [];
  const ids = new Set<string>();
  for (const candidate of value) {
    const action = responseActionFromRecord(candidate);
    if (!action || ids.has(action.id)) return null;
    ids.add(action.id);
    actions.push(action);
  }
  return actions;
};

const producerFromRecord = (value: unknown): SecurityProducer | null => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const id = stringField(record, "id");
  const label = stringField(record, "label");
  if (!id || !label) return null;
  const description = stringField(record, "description");
  const repo = stringField(record, "repo");
  const runtimeIds = stringListField(record, "runtimeIds");
  const sourceIds = stringListField(record, "sourceIds");
  const mcpTools = stringListField(record, "mcpTools");
  const resourceTemplates = stringListField(record, "resourceTemplates");
  const contextKeys = stringListField(record, "contextKeys");
  const responseActions = responseActionList(record);
  if (
    description === null || repo === null || !runtimeIds || !sourceIds || !mcpTools ||
    !resourceTemplates || !contextKeys || !responseActions
  ) return null;
  return {
    id,
    label,
    description: description || undefined,
    repo,
    runtimeIds,
    sourceIds,
    mcpTools,
    resourceTemplates,
    contextKeys,
    responseActions,
  };
};

export const securityProducerCatalogFromValue = (value: unknown): SecurityProducerCatalog => {
  if (!Array.isArray(value)) return { state: "invalid" };
  const producers: SecurityProducer[] = [];
  const ids = new Set<string>();
  const actionIDs = new Set<string>();
  const runtimeOwners = new Map<string, string>();
  const sourceOwners = new Map<string, string>();
  for (const candidate of value) {
    const producer = producerFromRecord(candidate);
    if (!producer || ids.has(producer.id)) return { state: "invalid" };
    if (producer.responseActions.some((action) => actionIDs.has(action.id))) {
      return { state: "invalid" };
    }
    if (
      producer.runtimeIds.some((runtimeID) => {
        const owner = runtimeOwners.get(runtimeID);
        return Boolean(owner && owner !== producer.id);
      }) ||
      producer.sourceIds.some((sourceID) => {
        const owner = sourceOwners.get(sourceID);
        return Boolean(owner && owner !== producer.id);
      })
    ) return { state: "invalid" };
    ids.add(producer.id);
    producer.responseActions.forEach((action) => actionIDs.add(action.id));
    producer.runtimeIds.forEach((runtimeID) => runtimeOwners.set(runtimeID, producer.id));
    producer.sourceIds.forEach((sourceID) => sourceOwners.set(sourceID, producer.id));
    producers.push(producer);
  }
  return { state: "ready", producers };
};

export const parseSecurityProducerCatalog = (raw?: string): SecurityProducerCatalog => {
  if (!raw?.trim()) return { state: "ready", producers: [] };
  try {
    return securityProducerCatalogFromValue(JSON.parse(raw) as unknown);
  } catch {
    return { state: "invalid" };
  }
};

export const defaultSecurityProducers: SecurityProducer[] = [];

export const mergeSecurityProducers = (
  defaults: SecurityProducer[],
  configured: SecurityProducer[],
): SecurityProducer[] => {
  const merged = [...defaults];
  for (const producer of configured) {
    const index = merged.findIndex((candidate) => candidate.id === producer.id);
    if (index === -1) {
      merged.push(producer);
    } else {
      merged[index] = producer;
    }
  }
  return merged;
};
