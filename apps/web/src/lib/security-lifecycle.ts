export type SecurityLifecycleResourceRef = {
  kind: string;
  id: string;
  revision?: string;
  state?: string;
};

export type SecurityLifecycleRecord = {
  observation: {
    subject_ref: SecurityLifecycleResourceRef;
    subject_kind: string;
    provider: string;
    authority_id: string;
    stable_locator: string;
    display_name: string;
    state: string;
    observed_at: string;
    issued_at?: string;
    expires_at?: string;
    rotated_at?: string;
    revoked_at?: string;
    owner_urn?: string;
    scope_refs?: SecurityLifecycleResourceRef[];
    evidence_claim_refs?: SecurityLifecycleResourceRef[];
    attributes?: Record<string, string>;
  };
  policy_evaluations?: Array<{
    policy_id: string;
    policy_version: string;
    subject_ref: SecurityLifecycleResourceRef;
    state: string;
    warning_window_days: number;
    seconds_until_expiry?: string | number;
    evaluated_at: string;
    evidence_claim_refs?: SecurityLifecycleResourceRef[];
  }>;
  findings?: Array<{
    finding_ref: SecurityLifecycleResourceRef;
    subject_ref: SecurityLifecycleResourceRef;
    finding_kind: string;
    status: string;
    evidence_claim_refs?: SecurityLifecycleResourceRef[];
  }>;
  action_routes?: Array<{
    finding_ref: SecurityLifecycleResourceRef;
    target_ref: SecurityLifecycleResourceRef;
    action_type: string;
    approval_required: boolean;
    action_intent_ref: SecurityLifecycleResourceRef;
    dispatch_ref: SecurityLifecycleResourceRef;
    verification_ref: SecurityLifecycleResourceRef;
  }>;
  projected_at?: string;
};

export type SecurityLifecycleResponse = {
  records: SecurityLifecycleRecord[];
  next_page_token?: string;
  previous_page_token?: string;
  truncated: boolean;
  as_of: string;
  aggregates?: {
    matched_records?: number;
    matched_findings?: number;
    subject_kind_counts?: Array<{ subject_kind: string; count: number }>;
    state_counts?: Array<{ state: string; count: number }>;
    policy_state_counts?: Array<{ policy_state: string; count: number }>;
    counts_are_exact?: boolean;
  };
  metadata?: {
    page_truncated?: boolean;
    coverage?: {
      complete?: boolean;
      truncated?: boolean;
      scanned_entities?: number;
      lifecycle_entities?: number;
      graph_revision?: string | number;
      reason?: string;
    };
    freshness?: {
      as_of?: string;
      oldest_observed_at?: string;
      newest_observed_at?: string;
    };
  };
};

export type SecurityLifecycleSummary = {
  expired: number;
  expiring: number;
  findings: number;
  ownerRequired: number;
};

export const lifecycleEnumLabel = (value: string) =>
  value
    .replace(/^SECURITY_LIFECYCLE_SUBJECT_KIND_/, "")
    .replace(/^SECURITY_LIFECYCLE_POLICY_STATE_/, "")
    .replace(/^SECURITY_LIFECYCLE_STATE_/, "")
    .toLowerCase();

export const lifecycleOwnerLabel = (owner?: string) => {
  if (!owner) return "Owner required";
  const parts = owner.split(":");
  const label = parts.at(-1) || owner;
  try {
    return decodeURIComponent(label);
  } catch {
    return label;
  }
};

export const lifecycleEffectiveState = (record: SecurityLifecycleRecord) =>
  lifecycleEnumLabel(
    record.policy_evaluations?.[0]?.state || record.observation.state,
  );

export const summarizeSecurityLifecycle = (
  records: SecurityLifecycleRecord[],
): SecurityLifecycleSummary =>
  records.reduce(
    (result, record) => {
      const current = lifecycleEffectiveState(record);
      if (current === "expired") result.expired += 1;
      if (current === "expiring") result.expiring += 1;
      if ((record.findings?.length ?? 0) > 0) result.findings += 1;
      if (!record.observation.owner_urn) result.ownerRequired += 1;
      return result;
    },
    { expired: 0, expiring: 0, findings: 0, ownerRequired: 0 },
  );

export const lifecycleExpiryLabel = (value?: string) => {
  if (!value) return "No expiry recorded";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  }).format(parsed);
};

export const lifecycleTimestampLabel = (value?: string) => {
  if (!value) return "Not reported";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(parsed);
};

export const lifecycleFindingID = (ref: SecurityLifecycleResourceRef) => {
  const raw = ref.id.split(":").at(-1) || ref.id;
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
};

export const lifecycleCompleteness = (response?: SecurityLifecycleResponse | null) => {
  const coverage = response?.metadata?.coverage;
  const pageTruncated = Boolean(
    response?.metadata?.page_truncated
    ?? response?.truncated
    ?? response?.next_page_token,
  );
  return {
    complete: coverage?.complete,
    pageTruncated,
    reason: coverage?.reason,
    sourceTruncated: Boolean(coverage?.truncated),
    total: response?.aggregates?.matched_records,
  };
};

export const lifecycleCoverageReason = (
  coverage?: NonNullable<SecurityLifecycleResponse["metadata"]>["coverage"],
) => coverage?.reason
    ?.replace(/^SECURITY_LIFECYCLE_COVERAGE_REASON_/, "")
    .toLowerCase();

export const lifecycleCoveragePresentation = (
  coverage?: NonNullable<SecurityLifecycleResponse["metadata"]>["coverage"],
) => {
  const reason = lifecycleCoverageReason(coverage);

  if (reason === "graph_changed") {
    return {
      label: "Graph changed during read",
      detail: "Refresh to load a consistent lifecycle snapshot.",
    };
  }
  if (reason === "scan_limit") {
    return {
      label: "Source coverage limited",
      detail: "The scan limit was reached before every lifecycle entity was evaluated.",
    };
  }
  if (reason === "complete" || coverage?.complete === true) {
    return {
      label: "Source coverage complete",
      detail: "Every lifecycle entity in this graph revision was evaluated.",
    };
  }
  if (coverage?.truncated) {
    return {
      label: "Source coverage truncated",
      detail: "The source scan ended before every lifecycle entity was evaluated.",
    };
  }
  return {
    label: "Source coverage not reported",
    detail: undefined,
  };
};

export const lifecycleNextPageToken = (response?: SecurityLifecycleResponse | null) =>
  response?.next_page_token || "";

export const lifecyclePreviousPageToken = (response?: SecurityLifecycleResponse | null) =>
  response?.previous_page_token || "";

export const lifecyclePolicyStateCount = (
  counts: Array<{ policy_state: string; count: number }> | undefined,
  value: string,
) => {
  if (!counts) return undefined;
  return counts.find((entry) => lifecycleEnumLabel(entry.policy_state) === value)?.count;
};

export const lifecycleActionLabel = (value: string) => {
  const normalized = lifecycleEnumLabel(value).replaceAll("_", " ");
  return normalized ? normalized[0].toUpperCase() + normalized.slice(1) : "External action";
};
