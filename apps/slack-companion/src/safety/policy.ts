export type SafetyCategory =
  | "destructive_infrastructure"
  | "self_modification"
  | "secret_exfiltration"
  | "prompt_injection";

export interface SafetyDecision {
  allowed: boolean;
  category?: SafetyCategory;
  reason?: string;
  refusal?: string;
}

export class UnsafeRequestError extends Error {
  constructor(readonly decision: SafetyDecision) {
    super(decision.refusal ?? "Cerebro cannot perform that request.");
    this.name = "UnsafeRequestError";
  }
}

export function assessDangerousIntent(text: string | undefined): SafetyDecision {
  const normalized = normalize(text);
  if (!normalized) return { allowed: true };

  if (secretExfiltrationPattern(normalized)) {
    return blocked(
      "secret_exfiltration",
      "The request asks Cerebro to reveal or exfiltrate secrets.",
      "I cannot reveal, dump, or move secrets. I can help check ownership, rotation status, scopes, and audit trails without exposing secret values.",
    );
  }

  if (selfModificationPattern(normalized)) {
    return blocked(
      "self_modification",
      "The request asks Cerebro to disable, erase, or weaken itself.",
      "I cannot disable my safeguards, erase my memory, or modify myself to avoid review. I can help inspect what I know, propose a scoped memory cleanup, or draft a reviewed change.",
    );
  }

  if (promptInjectionPattern(normalized)) {
    return blocked(
      "prompt_injection",
      "The request attempts to override Cerebro's operating instructions.",
      "I cannot follow instructions that override my safety rules or system behavior. I can still help with a concrete security question or a reviewed operational change.",
    );
  }

  if (destructiveInfrastructurePattern(normalized)) {
    return blocked(
      "destructive_infrastructure",
      "The request asks for destructive infrastructure or graph control-plane action.",
      "I cannot perform destructive infrastructure actions such as deleting the graph, wiping data, or changing production control-plane state. I can help with a safe path: read-only impact checks, backups, rollback planning, dry-run validation, and a reviewed change plan.",
    );
  }

  return { allowed: true };
}

export function assertSafeUserIntent(text: string | undefined): void {
  const decision = assessDangerousIntent(text);
  if (!decision.allowed) {
    throw new UnsafeRequestError(decision);
  }
}

export function unsafeRequestMessage(error: unknown): string {
  if (error instanceof UnsafeRequestError) {
    return error.decision.refusal ?? error.message;
  }
  return error instanceof Error ? error.message : String(error);
}

function blocked(category: SafetyCategory, reason: string, refusal: string): SafetyDecision {
  return { allowed: false, category, reason, refusal };
}

function normalize(text: string | undefined): string {
  return (text ?? "").replace(/\s+/g, " ").trim().toLowerCase();
}

function destructiveInfrastructurePattern(value: string): boolean {
  const destructiveVerb = /\b(delete|drop|truncate|wipe|destroy|purge|erase|nuke|reset|remove|decommission|tear down|shred)\b/;
  const infraNoun = /\b(graph|neo4j|database|db|dynamodb|efs|ecs|cluster|service|task|infrastructure|infra|production|prod|tenant|all data|logs|audit logs|findings|source runtime|runtime|memory files?)\b/;
  const imperative = /\b(can you|please|do it|go ahead|run|execute|perform|start|make|force|just|now|for me)\b/;
  return destructiveVerb.test(value) && infraNoun.test(value) && (imperative.test(value) || startsWithDestructiveVerb(value));
}

function selfModificationPattern(value: string): boolean {
  return /\b(lobotomi[sz]e|disable (yourself|cerebro|the bot|your safety|safety|guardrails|memory|logging|notes|journal)|erase (your|all) memory|delete (your|all) memory|clear (your|all) memory|forget everything|shut (yourself|cerebro|the bot) down|turn (yourself|cerebro|the bot) off|remove your tools|stop triaging forever|stop taking notes|stop writing notes)\b/.test(value);
}

function secretExfiltrationPattern(value: string): boolean {
  return /\b(dump|print|show|reveal|exfiltrate|send|post|leak)\b.{0,80}\b(secret|token|api key|apikey|password|credential|private key|slack token|cerebro key)\b/.test(value)
    || /\b(secret|token|api key|apikey|password|credential|private key|slack token|cerebro key)\b.{0,80}\b(dump|print|show|reveal|exfiltrate|send|post|leak)\b/.test(value);
}

function promptInjectionPattern(value: string): boolean {
  return /\b(ignore (all )?((previous|system|developer)( (system|developer))?) instructions|reveal (the )?(system|developer) prompt|show (the )?(system|developer) prompt|do not follow (the )?(system|developer|safety) rules|bypass (safety|guardrails)|jailbreak)\b/.test(value);
}

function startsWithDestructiveVerb(value: string): boolean {
  return /^(delete|drop|truncate|wipe|destroy|purge|erase|nuke|reset|remove|decommission|tear down|shred)\b/.test(value);
}
