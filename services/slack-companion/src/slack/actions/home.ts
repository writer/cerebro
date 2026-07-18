import { actionIds } from "../blocks/index.js";
import { publishHome } from "../home.js";
import type { ActionDeps } from "./types.js";

export function registerHomeActions(app: any, deps: ActionDeps): void {
  app.action(actionIds.refreshHome, async ({ body, ack, client }: any) => {
    await ack();
    await publishHome(client, body.user.id, deps.config, deps.cerebro, deps.a2a);
  });
}
