// Field names are snake_case because the API marshals protobuf with
// UseProtoNames.
export type FindingRuleSpec = {
  id: string;
  name?: string;
  description?: string;
  input_stream_ids?: string[];
  output_kinds?: string[];
};

// Synthetic streams carrying a pass/fail verdict decided elsewhere, rather
// than state collected by a connector.
export const externalVerdictStreams = new Set(["policy.evidence", "policy.result"]);

// True when every stream a rule listens to is an external verdict, so nothing
// a source collects can trigger it.
export const awaitsExternalVerdict = (rule: FindingRuleSpec) => {
  const streams = rule.input_stream_ids ?? [];
  if (streams.length === 0) return false;
  return streams.every((stream) => externalVerdictStreams.has(stream));
};
