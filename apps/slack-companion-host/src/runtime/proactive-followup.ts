import type { RustProactiveFollowupOffer } from "./cerebro-ask-client.js";
import {
  FileProactiveFollowupStore,
  type ProactiveFollowupAcceptance,
  type ProactiveFollowupDeliveryRecord,
  type ProactiveFollowupDeliveryReceipt,
} from "./proactive-followup-store.js";

/** Thin transport coordinator. Rust owns offer semantics and acceptance authority. */
export class ProactiveFollowupCoordinator {
  constructor(
    readonly store: FileProactiveFollowupStore,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  async prepareDelivery(
    offer: RustProactiveFollowupOffer,
  ): Promise<ProactiveFollowupDeliveryRecord> {
    return this.store.prepare(offer);
  }

  async markDeliveredForTurn(
    sourceRequestId: string,
    receipt: ProactiveFollowupDeliveryReceipt,
  ): Promise<ProactiveFollowupDeliveryRecord | undefined> {
    return this.store.markDeliveredForTurn(sourceRequestId, receipt);
  }

  async offerForTurn(sourceRequestId: string): Promise<RustProactiveFollowupOffer | undefined> {
    return (await this.store.list()).find((record) =>
      record.sourceRequestId === sourceRequestId
    )?.offer;
  }

  async beginAcceptance(input: {
    actorRef: string;
    ingressRequestKey: string;
    offerRef: string;
    threadRef: string;
  }): Promise<ProactiveFollowupAcceptance | undefined> {
    return this.store.beginAcceptance({
      ...input,
      attemptedAt: this.clock().toISOString(),
    });
  }

  async acknowledgeAcceptance(
    acceptance: ProactiveFollowupAcceptance,
    acceptedFollowupRef: string,
  ): Promise<void> {
    await this.store.markAccepted(
      acceptance.recordRef,
      acceptance.claim.ingressRequestKey,
      acceptedFollowupRef,
    );
  }

  async releaseAcceptance(acceptance: ProactiveFollowupAcceptance): Promise<void> {
    await this.store.releaseAcceptance(
      acceptance.recordRef,
      acceptance.claim.ingressRequestKey,
    );
  }
}
