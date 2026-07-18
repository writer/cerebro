import type { WebClient } from "@slack/web-api";
import type { AppConfig } from "../config/index.js";
import type { CerebroClient } from "../cerebro/client.js";
import { homeBlocks } from "./blocks/index.js";
import type { A2AFleetService } from "../a2a/index.js";

export async function publishHome(client: WebClient, userId: string, config: AppConfig, cerebro: CerebroClient, a2a?: A2AFleetService): Promise<void> {
  const runtimeIds = config.cerebro.defaultRuntimeIds;
  const [runtimeHealth, findings, fleetResult] = await Promise.all([
    captureSource(cerebro.listRuntimeHealth({
      runtimeIds,
      limit: Math.max(runtimeIds.length, 10),
    })),
    Promise.all(runtimeIds.slice(0, 5).map(async (runtimeId) => ({
      runtimeId,
      result: await captureSource(cerebro.listFindings(runtimeId, { limit: 3 })),
    }))),
    a2a ? captureSource(a2a.listInstances()) : Promise.resolve({ ok: false } as const),
  ]);
  const failedFindingRuntimeIds = findings.filter((item) => !item.result.ok).map((item) => item.runtimeId);
  const sourceFailures = [
    ...(!runtimeHealth.ok ? ["Runtime health"] : []),
    ...(failedFindingRuntimeIds.length ? [`Open findings for ${failedFindingRuntimeIds.join(", ")}`] : []),
  ];
  await client.views.publish({
    user_id: userId,
    view: {
      type: "home",
      blocks: homeBlocks({
        runtimes: runtimeHealth.ok ? runtimeHealth.value : [],
        findingsByRuntime: findings.flatMap((item) => item.result.ok ? [{ runtimeId: item.runtimeId, findings: item.result.value }] : []),
        fleet: fleetResult.ok ? fleetResult.value : undefined,
        sourceFailures,
        config,
      }) as any,
    },
  });
}

type SourceResult<T> = { ok: true; value: T } | { ok: false };

async function captureSource<T>(request: Promise<T>): Promise<SourceResult<T>> {
  try {
    return { ok: true, value: await request };
  } catch {
    return { ok: false };
  }
}
