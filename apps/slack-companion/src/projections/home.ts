import {
  contentBoundSlackIdentifier,
  normalizeSlackText,
  projectSlackBlocks,
  requireSlackKey,
  stableSlackIdentifier,
  type SlackActionInputV1,
  type SlackBlockV1,
} from "./blocks.js";
import type { SlackStatusProjectionV1 } from "./status.js";

const MAX_HOME_STATUSES = 20;

export interface SlackHomeInputV1 {
  readonly actions?: readonly SlackActionInputV1[];
  readonly projection_key: string;
  readonly statuses: readonly SlackStatusProjectionV1[];
  readonly summary: string;
  readonly title: string;
  /**
   * Bounded opaque identity for one Home view. Hosts may bind installation and
   * user identity into this selector; it is only a cache key, never authorization.
   */
  readonly view_selector: string;
}

export interface SlackHomeViewV1 {
  readonly blocks: readonly SlackBlockV1[];
  readonly external_id: string;
  readonly type: "home";
}

export interface SlackHomeProjectionV1 {
  readonly projection_id: string;
  readonly schema_version: "slack-home-projection/v1";
  readonly status_projection_ids: readonly string[];
  readonly view: SlackHomeViewV1;
}

export class SlackHomeProjectionError extends Error {}

export function projectSlackHome(
  input: SlackHomeInputV1,
): SlackHomeProjectionV1 {
  const projectionKey = requireSlackKey(input.projection_key, "home projection key");
  const viewSelector = requireSlackKey(input.view_selector, "home view selector");
  if (!Array.isArray(input.statuses) || input.statuses.length > MAX_HOME_STATUSES) {
    throw new SlackHomeProjectionError(
      `Slack Home cannot contain more than ${MAX_HOME_STATUSES} statuses.`,
    );
  }
  const statusIds = new Set<string>();
  const statuses = [...input.statuses]
    .map((status) => {
      if (status.schema_version !== "slack-status-projection/v1") {
        throw new SlackHomeProjectionError(
          "Slack Home status projection version is unsupported.",
        );
      }
      const projectionId = requireSlackKey(
        status.projection_id,
        "home status projection_id",
      );
      if (statusIds.has(projectionId)) {
        throw new SlackHomeProjectionError(
          "Slack Home status projection ids must be unique.",
        );
      }
      statusIds.add(projectionId);
      return {
        code: normalizeSlackText(status.code, "home status code", 80),
        observed_at: requireCanonicalTimestamp(
          status.observed_at,
          "home status observed_at",
        ),
        projection_id: projectionId,
        text: normalizeSlackText(status.text, "home status text", 600),
      };
    })
    .sort((left, right) =>
      compareStrings(left.observed_at, right.observed_at)
      || compareStrings(left.code, right.code)
      || compareStrings(left.projection_id, right.projection_id)
    );
  const sections = [
    normalizeSlackText(input.summary, "home summary", 3_000),
    ...statuses.map(
      (status) => `${formatStatusCode(status.code)}: ${status.text}`,
    ),
  ];
  const blockProjection = projectSlackBlocks({
    ...(input.actions === undefined ? {} : { actions: input.actions }),
    projection_key: `${projectionKey}:home`,
    sections,
    title: normalizeSlackText(input.title, "home title", 150),
  });
  const view = Object.freeze({
    blocks: blockProjection.blocks,
    external_id: stableSlackIdentifier("home", [viewSelector]),
    type: "home" as const,
  });
  const statusProjectionIds = Object.freeze(
    statuses.map((status) => status.projection_id),
  );
  const truth = {
    schema_version: "slack-home-projection/v1" as const,
    status_projection_ids: statusProjectionIds,
    view,
  };
  return Object.freeze({
    ...truth,
    projection_id: contentBoundSlackIdentifier("home", projectionKey, truth),
  });
}

function formatStatusCode(code: string): string {
  const words = code.replace(/^assistant_/, "").split("_");
  return words
    .map((word) => `${word.charAt(0).toUpperCase()}${word.slice(1)}`)
    .join(" ");
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function requireCanonicalTimestamp(value: string, field: string): string {
  const normalized = normalizeSlackText(value, field, 64);
  const parsed = Date.parse(normalized);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== normalized) {
    throw new SlackHomeProjectionError(
      `${field} must be a canonical ISO-8601 timestamp.`,
    );
  }
  return normalized;
}
