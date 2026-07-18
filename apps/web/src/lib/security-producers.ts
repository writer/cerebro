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

const stringValue = (value: unknown) => (typeof value === "string" ? value.trim() : "");

const stringList = (value: unknown) =>
  Array.isArray(value)
    ? value.map(stringValue).filter(Boolean)
    : [];

const boolValue = (value: unknown, fallback: boolean) =>
  typeof value === "boolean" ? value : fallback;

const responseActionFromRecord = (value: unknown): SecurityProducerResponseAction | null => {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  const id = stringValue(record.id);
  const label = stringValue(record.label);
  if (!id || !label) return null;
  return {
    id,
    label,
    providers: stringList(record.providers),
    targetTypes: stringList(record.targetTypes),
    requiredContextKeys: stringList(record.requiredContextKeys),
    mode: stringValue(record.mode) || "external_workflow",
    mcpTool: stringValue(record.mcpTool) || undefined,
    runtimeAction: stringValue(record.runtimeAction) || undefined,
    externalOwner: stringValue(record.externalOwner) || undefined,
    dryRun: boolValue(record.dryRun, true),
    requiresApproval: boolValue(record.requiresApproval, true),
  };
};

const responseActionList = (value: unknown) =>
  Array.isArray(value)
    ? value.map(responseActionFromRecord).filter((action): action is SecurityProducerResponseAction => Boolean(action))
    : [];

const producerFromRecord = (value: unknown): SecurityProducer | null => {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  const id = stringValue(record.id);
  const label = stringValue(record.label);
  if (!id || !label) return null;
  return {
    id,
    label,
    description: stringValue(record.description) || undefined,
    repo: stringValue(record.repo),
    runtimeIds: stringList(record.runtimeIds),
    sourceIds: stringList(record.sourceIds),
    mcpTools: stringList(record.mcpTools),
    resourceTemplates: stringList(record.resourceTemplates),
    contextKeys: stringList(record.contextKeys),
    responseActions: responseActionList(record.responseActions),
  };
};

export const securityProducersFromValue = (value: unknown): SecurityProducer[] =>
  Array.isArray(value)
    ? value.map(producerFromRecord).filter((producer): producer is SecurityProducer => Boolean(producer))
    : [];

export const parseSecurityProducers = (raw?: string): SecurityProducer[] => {
  if (!raw) return [];
  try {
    return securityProducersFromValue(JSON.parse(raw) as unknown);
  } catch {
    return [];
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

export const securityProducers = defaultSecurityProducers;
