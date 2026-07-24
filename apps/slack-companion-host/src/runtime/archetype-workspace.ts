import type { HomeView, ModalView } from "@slack/types";
import {
  ARCHETYPE_SLACK_ACTION_REGISTRY,
  decodeSlackActionEnvelope,
  decideSlackAction,
  projectArchetypeStartWorkConfirmation,
  projectArchetypeToday,
  type SlackActionEnvelopeV1,
} from "@writer/cerebro-slack-companion";

import {
  ArchetypeWorkspaceClient,
  ArchetypeWorkspaceClientError,
  type SlackUserLookupPort,
} from "../archetype-client.js";

const ARCHETYPE_CAPABILITY = Object.freeze({
  capability_id: "archetype.findings.assign_self",
  level: "required" as const,
  version: "v1",
});

export class ArchetypeSlackWorkspace {
  constructor(private readonly client: ArchetypeWorkspaceClient) {}

  async home(input: {
    slack: SlackUserLookupPort;
    teamId: string;
    userId: string;
  }): Promise<HomeView> {
    const identity = await this.client.resolveIdentity(input);
    const digest = await this.client.dailyDigest(identity);
    const projection = projectArchetypeToday(digest);
    return {
      blocks: [...projection.blocks.blocks],
      external_id: `archetype-today-${digestId([
        input.userId,
        projection.generated_at,
      ].join(":"))}`,
      type: "home",
    };
  }

  async preview(input: {
    actionValue: string;
    slack: SlackUserLookupPort;
    teamId: string;
    userId: string;
  }): Promise<ModalView> {
    const action = admittedAction(
      input.actionValue,
      "archetype.start_work.preview",
      "archetype_start_work_preview",
    );
    const findingRef = subjectIdentifier(
      action,
      "archetype-finding://",
      "finding",
    );
    const identity = await this.client.resolveIdentity(input);
    const intent = await this.client.createStartWorkIntent(identity, findingRef);
    if (intent.finding_ref !== findingRef) {
      throw new ArchetypeWorkspaceClientError(
        "Archetype returned a preview for a different finding.",
        "source_rejected",
      );
    }
    const confirmation = projectArchetypeStartWorkConfirmation(intent);
    return {
      blocks: [
        {
          text: {
            text: confirmation.summary,
            type: "mrkdwn",
          },
          type: "section",
        },
        {
          elements: [{
            action_id: confirmation.action.action_key,
            style: "primary",
            text: {
              emoji: true,
              text: confirmation.action.label,
              type: "plain_text",
            },
            type: "button",
            value: confirmation.action.value,
          }],
          type: "actions",
        },
        {
          elements: [{
            text: `This confirmation expires ${confirmation.expires_at}.`,
            type: "mrkdwn",
          }],
          type: "context",
        },
      ],
      callback_id: "archetype_start_work_confirmation",
      close: {
        emoji: true,
        text: "Cancel",
        type: "plain_text",
      },
      title: {
        emoji: true,
        text: "Confirm assignment",
        type: "plain_text",
      },
      type: "modal",
    };
  }

  async confirm(input: {
    actionValue: string;
    slack: SlackUserLookupPort;
    teamId: string;
    userId: string;
  }): Promise<ModalView> {
    const action = admittedAction(
      input.actionValue,
      "archetype.start_work.confirm",
      "archetype_start_work_confirm",
    );
    const intentId = subjectIdentifier(
      action,
      "archetype-intent://",
      "action intent",
    );
    const identity = await this.client.resolveIdentity(input);
    const execution = await this.client.executeStartWorkIntent(
      identity,
      intentId,
    );
    if (execution.intent.id !== intentId) {
      throw new ArchetypeWorkspaceClientError(
        "Archetype returned a different action result.",
        "source_rejected",
      );
    }
    const assignee = execution.finding.assignee;
    if (
      !assignee
      || assignee.kind !== "user"
      || assignee.source !== "okta"
      || assignee.id !== identity.oktaUserId
    ) {
      throw new ArchetypeWorkspaceClientError(
        "Archetype did not confirm the active Okta assignment.",
        "source_rejected",
      );
    }
    return statusModal(
      "Assignment recorded",
      `Assigned to ${assignee.display_name} in Archetype. Status: ${displayState(execution.finding.status)}.`,
    );
  }
}

export function archetypeLoadingModal(): ModalView {
  return statusModal("Checking assignment", "Checking your current Okta identity and finding state.");
}

export function archetypeErrorModal(error: unknown): ModalView {
  const state = archetypeErrorState(error);
  return statusModal(state.title, state.message);
}

export function archetypeUnavailableHome(error: unknown): HomeView {
  const state = archetypeErrorState(error);
  return {
    blocks: [
      {
        text: {
          emoji: true,
          text: "Archetype · Today",
          type: "plain_text",
        },
        type: "header",
      },
      {
        text: {
          text: state.message,
          type: "mrkdwn",
        },
        type: "section",
      },
    ],
    type: "home",
  };
}

function archetypeErrorState(error: unknown): {
  message: string;
  title: string;
} {
  if (error instanceof ArchetypeWorkspaceClientError) {
    switch (error.state) {
      case "identity_unavailable":
        return {
          message: "Okta could not verify your account. No finding changed.",
          title: "Identity check unavailable",
        };
      case "identity_unverified":
        return {
          message: "Your signed-in Slack account does not map to an active allowed Okta user. No finding changed.",
          title: "Account not verified",
        };
      case "source_rejected":
        return {
          message: "Archetype rejected the current identity or finding state. Refresh Today before trying again.",
          title: "Action not accepted",
        };
      case "source_unavailable":
        return {
          message: "Archetype could not confirm the current finding state. No finding changed.",
          title: "Archetype unavailable",
        };
    }
  }
  return {
    message: "The assignment could not be prepared. No finding changed.",
    title: "Action unavailable",
  };
}

function admittedAction(
  value: string,
  expectedAction: string,
  expectedCommand: string,
): SlackActionEnvelopeV1 {
  const action = decodeSlackActionEnvelope(value);
  if (action.action !== expectedAction || action.command !== expectedCommand) {
    throw new ArchetypeWorkspaceClientError(
      "The Archetype action does not match the requested operation.",
      "source_rejected",
    );
  }
  const decision = decideSlackAction(ARCHETYPE_SLACK_ACTION_REGISTRY, {
    action,
    available_capabilities: [ARCHETYPE_CAPABILITY],
  });
  if (decision.disposition !== "admit") {
    throw new ArchetypeWorkspaceClientError(
      "The Archetype action is not authorized.",
      "source_rejected",
    );
  }
  return action;
}

function subjectIdentifier(
  action: SlackActionEnvelopeV1,
  prefix: string,
  field: string,
): string {
  const subject = action.subject_ref;
  if (!subject?.startsWith(prefix)) {
    throw new ArchetypeWorkspaceClientError(
      `The Archetype ${field} reference is invalid.`,
      "source_rejected",
    );
  }
  const id = subject.slice(prefix.length);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
    throw new ArchetypeWorkspaceClientError(
      `The Archetype ${field} reference is invalid.`,
      "source_rejected",
    );
  }
  return id.toLowerCase();
}

function statusModal(title: string, message: string): ModalView {
  return {
    blocks: [{
      text: {
        text: message,
        type: "mrkdwn",
      },
      type: "section",
    }],
    close: {
      emoji: true,
      text: "Close",
      type: "plain_text",
    },
    title: {
      emoji: true,
      text: title,
      type: "plain_text",
    },
    type: "modal",
  };
}

function digestId(value: string): string {
  return Buffer.from(value).toString("base64url").slice(0, 80);
}

function displayState(value: string): string {
  return value.replaceAll("_", " ");
}
