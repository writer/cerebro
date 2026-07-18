export interface ParsedInvestigationObjective {
  runtimeId?: string;
  findingId?: string;
  assumptions: string[];
}

export function parseInvestigationObjective(objective: string, defaultRuntimeIds: string[]): ParsedInvestigationObjective {
  const assumptions: string[] = [];
  const runtimeId = defaultRuntimeIds.find((runtime) => objective.includes(runtime))
    ?? objective.match(/\bruntime(?:[_ -]?id)?[:=\s]+([A-Za-z0-9_.:-]+)/i)?.[1];
  const explicitFinding = objective.match(/\b(?:finding(?:[_ -]?id)?|fid)[:#=\s]+([A-Za-z0-9_.:-]+)/i)?.[1];
  const implicitFinding = objective.match(/\b([A-Za-z0-9_.:-]*finding[-_:][A-Za-z0-9_.:-]+)\b/i)?.[1];
  const findingId = explicitFinding && explicitFinding.toLowerCase() !== "finding"
    ? explicitFinding
    : implicitFinding;
  if (findingId && !runtimeId && defaultRuntimeIds.length === 1) {
    assumptions.push(`Assumed runtime ${defaultRuntimeIds[0]} because it is the only configured default runtime.`);
    return { runtimeId: defaultRuntimeIds[0], findingId, assumptions };
  }
  if (findingId && !runtimeId) {
    assumptions.push("Finding id was detected, but no runtime id was present. Ran broader context investigation.");
  }
  return { runtimeId, findingId, assumptions };
}
