import { Buffer } from "node:buffer";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  normalizeScratchpadContent,
  recordSlackThreadWorkingTurn,
  SLACK_THREAD_SCRATCHPAD_LIMITS,
  SlackThreadScratchpadError,
  validateSlackThreadScratchpad,
  type AddSlackThreadScratchpadNote,
  type AddSlackThreadScratchpadNoteResult,
  type RecordSlackThreadWorkingTurn,
  type SlackThreadScratchpadNoteV1,
  type SlackThreadScratchpadPort,
  type SlackThreadScratchpadV1,
  type SlackThreadWorkingStateV1,
} from "@writer/cerebro-slack-companion";

const WORKING_STATE_FILE = "working-state.json";

export interface FileThreadScratchpadStoreOptions {
  clock?: () => Date;
}

export class FileThreadScratchpadStore implements SlackThreadScratchpadPort {
  private readonly clock: () => Date;
  private mutationQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly root: string,
    options: FileThreadScratchpadStoreOptions = {},
  ) {
    this.clock = options.clock ?? (() => new Date());
  }

  async add(input: AddSlackThreadScratchpadNote): Promise<AddSlackThreadScratchpadNoteResult> {
    return this.serialize(async () => {
      const scratchpad = await this.read(input.thread_ref);
      const normalizedInput = input.content.replace(/\s+/gu, " ").trim();
      const content = normalizeScratchpadContent(input.content);
      const redacted = content !== normalizedInput;
      validateSource(input);
      const noteId = `slack-note://sha256/${digest(input.idempotency_key)}`;
      const current = scratchpad.notes.find((note) => note.note_id === noteId);
      if (current) {
        if (
          current.content !== content
          || current.author_ref !== input.author_ref
          || current.evidence_ref !== input.evidence_ref
          || current.source !== input.source
        ) {
          throw new SlackThreadScratchpadError(
            "The scratchpad request changed content for an existing identity.",
          );
        }
        return { created: false, note: current, redacted };
      }
      const totalBytes = scratchpad.notes.reduce(
        (total, note) => total + Buffer.byteLength(note.content, "utf8"),
        0,
      );
      const contentBytes = Buffer.byteLength(content, "utf8");
      if (
        scratchpad.notes.length >= SLACK_THREAD_SCRATCHPAD_LIMITS.max_notes
        || totalBytes + contentBytes
          > SLACK_THREAD_SCRATCHPAD_LIMITS.max_total_utf8_bytes
      ) {
        throw new SlackThreadScratchpadError(
          "This thread's scratchpad is full. Clear it before adding another note.",
        );
      }
      const createdAt = this.clock();
      const note: SlackThreadScratchpadNoteV1 = Object.freeze({
        author_ref: input.author_ref,
        content,
        created_at: createdAt.toISOString(),
        ...(input.evidence_ref === undefined
          ? {}
          : { evidence_ref: input.evidence_ref }),
        expires_at: new Date(
          createdAt.getTime() + SLACK_THREAD_SCRATCHPAD_LIMITS.lifetime_ms,
        ).toISOString(),
        note_id: noteId,
        schema_version: "slack-thread-scratchpad-note/v1",
        source: input.source,
        thread_ref: input.thread_ref,
      });
      validateSlackThreadScratchpad({
        notes: [...scratchpad.notes, note],
        schema_version: "slack-thread-scratchpad/v1",
        thread_ref: input.thread_ref,
        ...(scratchpad.working_state === undefined
          ? {}
          : { working_state: scratchpad.working_state }),
      }, createdAt);
      await this.atomicWrite(this.notePath(input.thread_ref, note.note_id), note);
      return { created: true, note, redacted };
    });
  }

  async clear(threadRef: string): Promise<number> {
    return this.serialize(async () => {
      const scratchpad = await this.read(threadRef);
      await rm(this.threadDirectory(threadRef), { force: true, recursive: true });
      return scratchpad.notes.length + (scratchpad.working_state === undefined ? 0 : 1);
    });
  }

  async recordWorkingTurn(
    input: RecordSlackThreadWorkingTurn,
  ): Promise<SlackThreadWorkingStateV1> {
    return this.serialize(async () => {
      const scratchpad = await this.read(input.thread_ref);
      const now = this.clock();
      const state = recordSlackThreadWorkingTurn(
        scratchpad.working_state,
        {
          ...(input.blocker === undefined ? {} : { blocker: input.blocker }),
          currentRequest: input.current_request,
          now,
          outcome: input.outcome,
          threadRef: input.thread_ref,
        },
      );
      validateSlackThreadScratchpad({
        notes: scratchpad.notes,
        schema_version: "slack-thread-scratchpad/v1",
        thread_ref: input.thread_ref,
        working_state: state,
      }, now);
      await this.atomicWrite(
        join(this.threadDirectory(input.thread_ref), WORKING_STATE_FILE),
        state,
      );
      return state;
    });
  }

  async read(threadRef: string): Promise<SlackThreadScratchpadV1> {
    const directory = this.threadDirectory(threadRef);
    let files: string[];
    try {
      files = (await readdir(directory)).filter((file) =>
        file.endsWith(".json") && file !== WORKING_STATE_FILE
      );
    } catch (error) {
      if (errorCode(error) === "ENOENT") return emptyScratchpad(threadRef);
      throw error;
    }
    const now = this.clock();
    const notes: SlackThreadScratchpadNoteV1[] = [];
    for (const file of files.sort()) {
      const path = join(directory, file);
      const decoded: unknown = JSON.parse(await readFile(path, "utf8"));
      const candidate = validateSlackThreadScratchpad({
        notes: [decoded as SlackThreadScratchpadNoteV1],
        schema_version: "slack-thread-scratchpad/v1",
        thread_ref: threadRef,
      }, now);
      if (candidate.notes.length === 0) {
        await rm(path, { force: true });
        continue;
      }
      notes.push(candidate.notes[0]!);
    }
    const workingStatePath = join(directory, WORKING_STATE_FILE);
    let workingState: SlackThreadWorkingStateV1 | undefined;
    try {
      workingState = JSON.parse(
        await readFile(workingStatePath, "utf8"),
      ) as SlackThreadWorkingStateV1;
    } catch (error) {
      if (errorCode(error) !== "ENOENT") throw error;
    }
    const scratchpad = validateSlackThreadScratchpad({
      notes,
      schema_version: "slack-thread-scratchpad/v1",
      thread_ref: threadRef,
      ...(workingState === undefined ? {} : { working_state: workingState }),
    }, now);
    if (workingState !== undefined && scratchpad.working_state === undefined) {
      await rm(workingStatePath, { force: true });
    }
    return scratchpad;
  }

  private async atomicWrite(path: string, value: unknown): Promise<void> {
    await mkdir(dirname(path), { recursive: true });
    const temporary = `${path}.${randomUUID()}.tmp`;
    await writeFile(temporary, `${JSON.stringify(value)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporary, path);
  }

  private notePath(threadRef: string, noteId: string): string {
    return join(this.threadDirectory(threadRef), `${digest(noteId)}.json`);
  }

  private threadDirectory(threadRef: string): string {
    return join(this.root, "scratchpads", digest(threadRef));
  }

  private async serialize<T>(operation: () => Promise<T>): Promise<T> {
    const prior = this.mutationQueue;
    let release!: () => void;
    this.mutationQueue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prior;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}

function validateSource(input: AddSlackThreadScratchpadNote): void {
  if (
    (input.source === "cerebro"
      && (
        input.evidence_ref === undefined
        || !input.evidence_ref.startsWith("cerebro-ask://sha256/")
      ))
    || (input.source === "human" && input.evidence_ref !== undefined)
  ) {
    throw new SlackThreadScratchpadError(
      "The scratchpad note source and evidence do not match.",
    );
  }
}

function emptyScratchpad(threadRef: string): SlackThreadScratchpadV1 {
  return Object.freeze({
    notes: Object.freeze([]),
    schema_version: "slack-thread-scratchpad/v1",
    thread_ref: threadRef,
  });
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function errorCode(value: unknown): string | undefined {
  return value !== null && typeof value === "object" && "code" in value
    ? String((value as { code?: unknown }).code)
    : undefined;
}
