import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { RustProactiveFollowupOffer } from "./cerebro-ask-client.js";

const STORE_SCHEMA_VERSION = "slack-proactive-followup-delivery/v1";

export interface ProactiveFollowupAcceptanceClaim {
  actorRef: string;
  attemptedAt: string;
  ingressRequestKey: string;
}

export interface ProactiveFollowupDeliveryReceipt {
  deliveredAt: string;
  deliveryRef: string;
  payloadDigest: string;
}

export interface ProactiveFollowupDeliveryRecord {
  acceptance?: ProactiveFollowupAcceptanceClaim;
  acceptedFollowupRef?: string;
  delivery?: ProactiveFollowupDeliveryReceipt;
  offer: RustProactiveFollowupOffer;
  offerDigest: string;
  recordRef: string;
  schemaVersion: typeof STORE_SCHEMA_VERSION;
  sourceRequestId: string;
  state: "accepted" | "accepting" | "delivered" | "prepared";
}

export interface ProactiveFollowupAcceptance {
  claim: ProactiveFollowupAcceptanceClaim;
  offer: RustProactiveFollowupOffer;
  recordRef: string;
}

export class FileProactiveFollowupStore {
  private mutationQueue: Promise<void> = Promise.resolve();

  constructor(private readonly root: string) {}

  async prepare(offer: RustProactiveFollowupOffer): Promise<ProactiveFollowupDeliveryRecord> {
    return this.serialize(async () => {
      validateOffer(offer);
      const sourceRequestId = offer.turn_ref.slice("agent-turn://".length);
      const offerDigest = jsonDigest(offer);
      const recordRef = recordIdentity(offer);
      const prepared: ProactiveFollowupDeliveryRecord = {
        offer,
        offerDigest,
        recordRef,
        schemaVersion: STORE_SCHEMA_VERSION,
        sourceRequestId,
        state: "prepared",
      };
      validateRecord(prepared);
      const current = await this.readRecord(recordRef);
      if (current) {
        if (
          current.offerDigest !== offerDigest
          || jsonDigest(current.offer) !== offerDigest
          || current.sourceRequestId !== sourceRequestId
        ) throw new Error("The proactive follow-up changed for an existing identity.");
        return current;
      }
      await this.write(prepared);
      return prepared;
    });
  }

  async markDeliveredForTurn(
    sourceRequestId: string,
    receipt: ProactiveFollowupDeliveryReceipt,
  ): Promise<ProactiveFollowupDeliveryRecord | undefined> {
    return this.serialize(async () => {
      validateDelivery(receipt);
      const current = (await this.list()).find((record) =>
        record.sourceRequestId === sourceRequestId && record.state === "prepared"
      );
      if (!current) {
        const replayed = (await this.list()).find((record) =>
          record.sourceRequestId === sourceRequestId && record.state !== "prepared"
        );
        if (replayed && JSON.stringify(replayed.delivery) !== JSON.stringify(receipt)) {
          throw new Error("The proactive follow-up delivery receipt changed.");
        }
        return replayed;
      }
      const delivered: ProactiveFollowupDeliveryRecord = {
        ...current,
        delivery: receipt,
        state: "delivered",
      };
      await this.write(delivered);
      return delivered;
    });
  }

  async list(): Promise<ProactiveFollowupDeliveryRecord[]> {
    let files: string[];
    try {
      files = (await readdir(this.directory())).filter((file) => file.endsWith(".json"));
    } catch (error) {
      if (errorCode(error) === "ENOENT") return [];
      throw error;
    }
    const records = await Promise.all(files.sort().map(async (file) =>
      validateRecord(JSON.parse(await readFile(join(this.directory(), file), "utf8")))
    ));
    return records.sort((left, right) => left.recordRef.localeCompare(right.recordRef));
  }

  async beginAcceptance(input: {
    actorRef: string;
    attemptedAt: string;
    ingressRequestKey: string;
    operatorText: string;
    threadRef: string;
  }): Promise<ProactiveFollowupAcceptance | undefined> {
    return this.serialize(async () => {
      requireText(input.actorRef, "accepting actor");
      requireText(input.ingressRequestKey, "acceptance request identity");
      requireText(input.threadRef, "acceptance thread identity");
      requireCanonicalTimestamp(input.attemptedAt, "acceptance time");
      const attemptedAt = Date.parse(input.attemptedAt);
      const normalizedAction = normalizeAction(input.operatorText);
      if (!normalizedAction) return undefined;
      const current = (await this.list()).reverse().find((record) =>
        record.offer.thread_ref === input.threadRef
        && normalizeAction(record.offer.action) === normalizedAction
        && record.state !== "prepared"
      );
      if (!current) return undefined;
      const createdAt = Date.parse(current.offer.created_at);
      const expiresAt = Date.parse(current.offer.expires_at);
      if (attemptedAt < createdAt || attemptedAt > expiresAt) return undefined;
      if (current.state === "accepting" || current.state === "accepted") {
        if (
          current.acceptance?.actorRef !== input.actorRef
          || current.acceptance.ingressRequestKey !== input.ingressRequestKey
        ) return undefined;
        return {
          claim: current.acceptance,
          offer: current.offer,
          recordRef: current.recordRef,
        };
      }
      const claim: ProactiveFollowupAcceptanceClaim = {
        actorRef: input.actorRef,
        attemptedAt: input.attemptedAt,
        ingressRequestKey: input.ingressRequestKey,
      };
      await this.write({ ...current, acceptance: claim, state: "accepting" });
      return { claim, offer: current.offer, recordRef: current.recordRef };
    });
  }

  async markAccepted(
    recordRef: string,
    ingressRequestKey: string,
    acceptedFollowupRef: string,
  ): Promise<ProactiveFollowupDeliveryRecord> {
    return this.serialize(async () => {
      const current = await this.requiredRecord(recordRef);
      if (
        (current.state !== "accepting" && current.state !== "accepted")
        || current.acceptance?.ingressRequestKey !== ingressRequestKey
        || acceptedFollowupRef !== current.offer.offer_ref
      ) throw new Error("The Rust follow-up acknowledgement does not match the acceptance.");
      if (current.state === "accepted") return current;
      const accepted = {
        ...current,
        acceptedFollowupRef,
        state: "accepted" as const,
      };
      await this.write(accepted);
      return accepted;
    });
  }

  async releaseAcceptance(recordRef: string, ingressRequestKey: string): Promise<void> {
    await this.serialize(async () => {
      const current = await this.requiredRecord(recordRef);
      if (current.state === "accepted") return;
      if (
        current.state !== "accepting"
        || current.acceptance?.ingressRequestKey !== ingressRequestKey
      ) throw new Error("The proactive follow-up acceptance claim changed.");
      const { acceptance: _, ...withoutAcceptance } = current;
      await this.write({ ...withoutAcceptance, state: "delivered" });
    });
  }

  private async requiredRecord(recordRef: string): Promise<ProactiveFollowupDeliveryRecord> {
    const record = await this.readRecord(recordRef);
    if (!record) throw new Error("The proactive follow-up record does not exist.");
    return record;
  }

  private async readRecord(
    recordRef: string,
  ): Promise<ProactiveFollowupDeliveryRecord | undefined> {
    try {
      return validateRecord(JSON.parse(await readFile(this.path(recordRef), "utf8")));
    } catch (error) {
      if (errorCode(error) === "ENOENT") return undefined;
      throw error;
    }
  }

  private async write(record: ProactiveFollowupDeliveryRecord): Promise<void> {
    validateRecord(record);
    const path = this.path(record.recordRef);
    await mkdir(dirname(path), { recursive: true });
    const temporary = `${path}.${randomUUID()}.tmp`;
    await writeFile(temporary, `${JSON.stringify(record)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporary, path);
  }

  private directory(): string {
    return join(this.root, "proactive-followup-deliveries");
  }

  private path(recordRef: string): string {
    return join(this.directory(), `${digest(recordRef)}.json`);
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

function validateRecord(value: unknown): ProactiveFollowupDeliveryRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The proactive follow-up record is invalid.");
  }
  const record = value as Record<string, unknown>;
  if (
    record.schemaVersion !== STORE_SCHEMA_VERSION
    || !["accepted", "accepting", "delivered", "prepared"].includes(String(record.state))
    || !/^slack-proactive-followup:\/\/sha256\/[a-f0-9]{64}$/u.test(
      requireText(record.recordRef, "record identity"),
    )
    || !/^sha256:[a-f0-9]{64}$/u.test(requireText(record.offerDigest, "offer digest"))
    || !boundedText(record.sourceRequestId, 2_048)
  ) throw new Error("The proactive follow-up record is invalid.");
  validateOffer(record.offer);
  const typed = record as unknown as ProactiveFollowupDeliveryRecord;
  if (
    typed.recordRef !== recordIdentity(typed.offer)
    || typed.sourceRequestId !== typed.offer.turn_ref.slice("agent-turn://".length)
    || typed.offerDigest !== jsonDigest(typed.offer)
  ) throw new Error("The proactive follow-up offer digest is invalid.");
  if (typed.state === "prepared") {
    if (typed.delivery !== undefined || typed.acceptance !== undefined) {
      throw new Error("A prepared proactive follow-up has a premature receipt.");
    }
  } else {
    validateDelivery(typed.delivery);
  }
  if (typed.state === "accepting" || typed.state === "accepted") {
    validateAcceptance(typed.acceptance);
  } else if (typed.acceptance !== undefined) {
    throw new Error("A non-accepting proactive follow-up has an acceptance claim.");
  }
  if (
    (typed.state === "accepted") !== (typed.acceptedFollowupRef !== undefined)
    || (typed.acceptedFollowupRef !== undefined
      && typed.acceptedFollowupRef !== typed.offer.offer_ref)
  ) throw new Error("The proactive follow-up acceptance acknowledgement is invalid.");
  return typed;
}

function validateOffer(value: unknown): asserts value is RustProactiveFollowupOffer {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The Rust proactive follow-up offer is invalid.");
  }
  const offer = value as Record<string, unknown>;
  const expected = [
    "action", "action_key", "created_at", "expires_at", "grounding_refs", "offer_ref",
    "schema_version", "tenant_id", "thread_ref", "title", "turn_ref",
  ].sort();
  const keys = Object.keys(offer).sort();
  if (
    keys.length !== expected.length
    || !keys.every((key, index) => key === expected[index])
    || offer.schema_version !== "proactive-followup-offer/v1"
    || !/^[a-z0-9][a-z0-9._:-]{0,127}$/u.test(requireText(offer.action_key, "action key"))
    || !Array.isArray(offer.grounding_refs)
    || offer.grounding_refs.length === 0
    || offer.grounding_refs.length > 16
    || offer.grounding_refs.some((reference) => !boundedText(reference, 2_048))
  ) throw new Error("The Rust proactive follow-up offer is invalid.");
  for (const [field, limit] of [
    ["action", 512], ["tenant_id", 2_048],
    ["thread_ref", 2_048], ["title", 512], ["turn_ref", 2_048],
  ] as const) {
    if (!boundedText(offer[field], limit)) {
      throw new Error(`The Rust proactive follow-up ${field} is invalid.`);
    }
  }
  if (!/^proactive-followup:\/\/sha256\/[a-f0-9]{64}$/u.test(String(offer.offer_ref))) {
    throw new Error("The Rust proactive follow-up offer reference is invalid.");
  }
  if (
    !String(offer.turn_ref).startsWith("agent-turn://")
    || String(offer.turn_ref).length === "agent-turn://".length
  ) {
    throw new Error("The Rust proactive follow-up turn reference is invalid.");
  }
  requireCanonicalTimestamp(offer.created_at, "offer creation time");
  requireCanonicalTimestamp(offer.expires_at, "offer expiry");
  if (Date.parse(String(offer.created_at)) >= Date.parse(String(offer.expires_at))) {
    throw new Error("The Rust proactive follow-up expiry is invalid.");
  }
}

function validateDelivery(value: unknown): asserts value is ProactiveFollowupDeliveryReceipt {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The proactive follow-up delivery receipt is invalid.");
  }
  const delivery = value as Record<string, unknown>;
  requireCanonicalTimestamp(delivery.deliveredAt, "delivery time");
  requireText(delivery.deliveryRef, "delivery identity");
  if (!/^sha256:[a-f0-9]{64}$/u.test(requireText(delivery.payloadDigest, "payload digest"))) {
    throw new Error("The proactive follow-up payload digest is invalid.");
  }
}

function validateAcceptance(value: unknown): asserts value is ProactiveFollowupAcceptanceClaim {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The proactive follow-up acceptance claim is invalid.");
  }
  const claim = value as Record<string, unknown>;
  requireText(claim.actorRef, "accepting actor");
  requireText(claim.ingressRequestKey, "acceptance request identity");
  requireCanonicalTimestamp(claim.attemptedAt, "acceptance time");
}

function recordIdentity(offer: RustProactiveFollowupOffer): string {
  return `slack-proactive-followup://sha256/${digest([
    offer.tenant_id, offer.thread_ref, offer.offer_ref,
  ].join("\n"))}`;
}

function normalizeAction(value: string): string {
  return value.replace(/\s+/gu, " ").trim().toLowerCase();
}

function boundedText(value: unknown, limit: number): value is string {
  return typeof value === "string"
    && Boolean(value.trim())
    && Buffer.byteLength(value, "utf8") <= limit;
}

function requireText(value: unknown, label: string): string {
  if (!boundedText(value, 8_192)) throw new Error(`The ${label} is invalid.`);
  return value;
}

function requireCanonicalTimestamp(value: unknown, label: string): asserts value is string {
  if (
    typeof value !== "string"
    || !Number.isFinite(Date.parse(value))
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value)
  ) throw new Error(`The ${label} is invalid.`);
}

function jsonDigest(value: unknown): string {
  return `sha256:${digest(JSON.stringify(value))}`;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}
