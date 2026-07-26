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
    state: string;
    warning_window_days: number;
    seconds_until_expiry?: string | number;
    evaluated_at: string;
  }>;
  findings?: Array<{
    finding_ref: SecurityLifecycleResourceRef;
    finding_kind: string;
    status: string;
  }>;
  action_routes?: Array<{
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
  truncated: boolean;
  as_of: string;
};

export const lifecycleEnumLabel = (value: string) =>
  value
    .replace(/^SECURITY_LIFECYCLE_SUBJECT_KIND_/, "")
    .replace(/^SECURITY_LIFECYCLE_STATE_/, "")
    .toLowerCase();

export const lifecycleOwnerLabel = (owner?: string) => {
  if (!owner) return "Owner required";
  const parts = owner.split(":");
  return decodeURIComponent(parts.at(-1) || owner);
};

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
