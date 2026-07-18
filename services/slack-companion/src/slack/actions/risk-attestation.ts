import type { RiskAttestationAnswer } from "../risk-attestation.js";
import { actionIds } from "../blocks/index.js";
import type { ActionDeps } from "./types.js";
import { errorMessage, payloadFromAction, required } from "./utils.js";

export function registerRiskAttestationActions(app: any, deps: ActionDeps): void {
  app.action(actionIds.riskAttestationResponse, async ({ body, action, ack, respond }: any) => {
    await ack();
    try {
      if (!deps.riskAttestations) throw new Error("Security check responses are not configured.");
      const payload = payloadFromAction(action, body);
      const result = await deps.riskAttestations.respond({
        id: required(payload.confirmationId, "security check id"),
        responderUserId: required(body.user?.id, "Slack user id"),
        answer: riskAttestationAnswer(payload.confirmationResponse),
      });
      if (!result.changed) {
        await respond?.({ response_type: "ephemeral", text: "Your answer was already recorded." });
      }
    } catch (error) {
      await respond?.({ response_type: "ephemeral", text: errorMessage(error) });
    }
  });
}

function riskAttestationAnswer(value: string | undefined): RiskAttestationAnswer {
  if (value === "yes" || value === "no" || value === "unsure") return value;
  throw new Error("Security check answer is invalid.");
}
