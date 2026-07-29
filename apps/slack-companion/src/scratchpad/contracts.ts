export const SLACK_THREAD_SCRATCHPAD_LIMITS = Object.freeze({
  lifetime_ms: 7 * 24 * 60 * 60 * 1_000,
  max_note_utf8_bytes: 900,
  max_notes: 20,
  max_recent_requests: 3,
  max_total_utf8_bytes: 8_000,
});

export type SlackThreadWorkingOutcome = "blocked" | "completed" | "needs_user";

export interface SlackThreadWorkingStateV1 {
  readonly blocker?: string;
  readonly expires_at: string;
  readonly last_outcome: SlackThreadWorkingOutcome;
  readonly recent_requests: readonly string[];
  readonly schema_version: "slack-thread-working-state/v1";
  readonly thread_ref: string;
  readonly updated_at: string;
}

export interface SlackThreadScratchpadNoteV1 {
  readonly author_ref: string;
  readonly content: string;
  readonly created_at: string;
  readonly evidence_ref?: string;
  readonly expires_at: string;
  readonly note_id: string;
  readonly schema_version: "slack-thread-scratchpad-note/v1";
  readonly source: "cerebro" | "human";
  readonly thread_ref: string;
}

export interface SlackThreadScratchpadV1 {
  readonly notes: readonly SlackThreadScratchpadNoteV1[];
  readonly schema_version: "slack-thread-scratchpad/v1";
  readonly thread_ref: string;
  readonly working_state?: SlackThreadWorkingStateV1;
}

export interface AddSlackThreadScratchpadNote {
  readonly author_ref: string;
  readonly content: string;
  readonly evidence_ref?: string;
  readonly idempotency_key: string;
  readonly source: "cerebro" | "human";
  readonly thread_ref: string;
}

export interface AddSlackThreadScratchpadNoteResult {
  readonly created: boolean;
  readonly note: SlackThreadScratchpadNoteV1;
  readonly redacted: boolean;
}

export interface RecordSlackThreadWorkingTurn {
  readonly blocker?: string;
  readonly current_request: string;
  readonly outcome: SlackThreadWorkingOutcome;
  readonly thread_ref: string;
}

export interface SlackThreadScratchpadPort {
  add(input: AddSlackThreadScratchpadNote): Promise<AddSlackThreadScratchpadNoteResult>;
  clear(threadRef: string): Promise<number>;
  recordWorkingTurn(input: RecordSlackThreadWorkingTurn): Promise<SlackThreadWorkingStateV1>;
  read(threadRef: string): Promise<SlackThreadScratchpadV1>;
}

export class SlackThreadScratchpadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SlackThreadScratchpadError";
  }
}
