import { createHash } from "crypto";

import {
  currentUserActor,
  currentUserAuditFields,
  type CurrentUser,
} from "@/lib/identity";

const actorKey = (user: CurrentUser | null | undefined) => {
  const actor = currentUserActor(user);
  if (!actor) return "";
  return createHash("sha256").update(`${user?.provider ?? "unknown"}:${actor}`).digest("hex").slice(0, 16);
};

export const currentUserServerAuditFields = (user: CurrentUser | null | undefined) => ({
  ...currentUserAuditFields(user),
  actorKey: actorKey(user),
  actorIdPresent: Boolean(user?.actorId),
  actorLabelPresent: Boolean(user?.actorLabel),
});
