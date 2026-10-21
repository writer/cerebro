"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

import { EmptyBlock, LoadingBlock, MetricCard, Panel } from "@/components/grc/Primitives";
import { useApiKey } from "@/components/providers";
import {
  ATTACK_SIMULATION_SCENARIOS,
  attackSimulationRequest,
  attackSimulationResult,
  attackSimulationScenarioFor,
  signedChange,
  simulationRuntimeIDs,
  tenantIDFromURN,
  type AttackSimulationPath,
  type AttackSimulationResult,
  type AttackSimulationScenarioID,
} from "@/lib/attack-simulation";
import { fetchCerebro } from "@/lib/cerebro-client";
import { shortEntity } from "@/lib/grc";
import { grcPath, grcResponseErrorMessage, useGRCQuery } from "@/lib/grc-client";

export type AttackSimulationTarget = { urn: string; label: string };

const changeIntent = (change: number, intent: "defend" | "attack") => {
  if (change === 0) return "neutral" as const;
  const better = change < 0;
  return (intent === "attack" ? !better : better) ? "success" as const : "danger" as const;
};

function PathList({ empty, paths, title }: { empty: string; paths: AttackSimulationPath[]; title: string }) {
  return (
    <div>
      <h3 className="text-[12px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{title} ({paths.length})</h3>
      {paths.length === 0 ? (
        <p className="mt-2 text-[13px] text-[var(--text-muted)]">{empty}</p>
      ) : (
        <ul className="mt-2 space-y-2">
          {paths.map((path, index) => (
            <li key={`${path.findingID}:${path.pattern}:${index}`} className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] px-3 py-2">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px]">
                {path.steps.map((step, stepIndex) => (
                  <span key={`${step.from}:${step.relation}:${step.to}`} className="flex items-center gap-2">
                    {stepIndex === 0 && (
                      <Link href={`/inventory/${encodeURIComponent(step.from)}`} prefetch={false} className="font-medium text-[var(--text-primary)] hover:underline">{shortEntity(step.from)}</Link>
                    )}
                    <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--text-muted)]">{step.relation || "reaches"} →</span>
                    <Link href={`/inventory/${encodeURIComponent(step.to)}`} prefetch={false} className="font-medium text-[var(--text-primary)] hover:underline">{shortEntity(step.to)}</Link>
                  </span>
                ))}
              </div>
              <div className="mt-1 text-[11px] text-[var(--text-muted)]">
                {[path.pattern, `score ${path.score}`, path.findingID && `finding ${path.findingID}`].filter(Boolean).join(" • ")}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function AttackSimulationPanel({
  defaultTargetURN,
  initialScenario,
  onScenarioChange,
  targets,
  tenantID,
}: {
  defaultTargetURN: string;
  initialScenario?: string;
  onScenarioChange?: (scenario: AttackSimulationScenarioID) => void;
  targets: AttackSimulationTarget[];
  tenantID: string;
}) {
  const { apiKey } = useApiKey();
  const [targetURN, setTargetURN] = useState(defaultTargetURN);
  const [scenarioID, setScenarioID] = useState<AttackSimulationScenarioID>(
    attackSimulationScenarioFor(initialScenario)?.id ?? "remove_public_exposure",
  );
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AttackSimulationResult | null>(null);

  const scenario = attackSimulationScenarioFor(scenarioID) ?? ATTACK_SIMULATION_SCENARIOS[0];
  // The report rejects a target from another tenant, so the target's own tenant wins over the page scope.
  const simulationTenantID = tenantIDFromURN(targetURN) || tenantID.trim();
  const runtimesQuery = useGRCQuery<unknown>(
    simulationTenantID ? grcPath("/source-runtimes", { tenant_id: simulationTenantID, limit: 200 }) : null,
  );
  const runtimeIDs = useMemo(() => simulationRuntimeIDs(runtimesQuery.data), [runtimesQuery.data]);
  const targetOptions = useMemo(() => {
    const seen = new Set<string>();
    return [{ urn: defaultTargetURN, label: shortEntity(defaultTargetURN) }, ...targets].filter((target) => {
      if (!target.urn || seen.has(target.urn)) return false;
      seen.add(target.urn);
      return true;
    });
  }, [defaultTargetURN, targets]);

  const blocker = !simulationTenantID
    ? "Choose a tenant, or start from a full urn:cerebro:<tenant>:... entity, to simulate."
    : runtimesQuery.loading && !runtimesQuery.data
      ? ""
      : runtimeIDs.length === 0
        ? "No source runtimes are connected for this tenant, so there are no findings to replay."
        : "";

  const run = async () => {
    if (blocker || running) return;
    setRunning(true);
    setError(null);
    const request = attackSimulationRequest({ runtimeIDs, scenario: scenario.id, targetURN, tenantID: simulationTenantID });
    try {
      const response = await fetchCerebro<unknown>(request.path, apiKey, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request.body),
      });
      if (!response.ok) {
        setError(grcResponseErrorMessage(request.path, response.status, response.data));
        setResult(null);
        return;
      }
      const parsed = attackSimulationResult(response.data);
      if (!parsed) {
        setError("The simulation returned no risk delta.");
        setResult(null);
        return;
      }
      setResult(parsed);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to run the simulation.");
      setResult(null);
    } finally {
      setRunning(false);
    }
  };

  const resultIsCurrent = result && result.targetURN === targetURN && result.scenario === scenario.id;

  return (
    <Panel
      title="Simulate"
      description="Apply one change to one entity and replay the tenant's findings and graph to see which attack paths open or close. Nothing in the graph or the source changes."
    >
      <div className="space-y-5">
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4" role="radiogroup" aria-label="Simulation scenario">
          {ATTACK_SIMULATION_SCENARIOS.map((entry) => {
            const active = entry.id === scenario.id;
            return (
              <button
                key={entry.id}
                type="button"
                role="radio"
                aria-checked={active}
                onClick={() => { setScenarioID(entry.id); onScenarioChange?.(entry.id); }}
                className={`rounded-lg border px-4 py-3 text-left transition ${
                  active
                    ? "border-[color:var(--primary)] bg-[var(--primary-soft)] shadow-[var(--shadow-sm)]"
                    : "border-[color:var(--border)] bg-[var(--surface)] hover:border-[color:var(--border-strong)]"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[13px] font-semibold text-[var(--text-primary)]">{entry.label}</span>
                  <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{entry.intent === "attack" ? "Attacker" : "Fix"}</span>
                </div>
                <div className="mt-1 text-[11px] leading-snug text-[var(--text-muted)]">{entry.question}</div>
              </button>
            );
          })}
        </div>

        <div className="flex flex-wrap items-end gap-3">
          <label className="min-w-[260px] flex-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
            Target entity
            <select
              value={targetURN}
              onChange={(event) => setTargetURN(event.target.value)}
              className="control-input mt-1 w-full px-3 py-1.5 text-[13px] normal-case tracking-normal"
            >
              {targetOptions.map((target) => <option key={target.urn} value={target.urn}>{target.label}</option>)}
            </select>
          </label>
          <button
            type="button"
            onClick={() => void run()}
            disabled={Boolean(blocker) || running || runtimesQuery.loading}
            className="primary-button px-4 py-1.5 text-[13px] disabled:cursor-not-allowed disabled:opacity-50"
          >
            {running ? "Simulating..." : "Run Simulation"}
          </button>
        </div>
        <div className="truncate font-mono text-[11px] text-[var(--text-muted)]" title={targetURN}>{targetURN}</div>

        {blocker && <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-[12px] text-amber-800">{blocker}</div>}
        {runtimesQuery.error && <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-[12px] text-amber-800">{runtimesQuery.error}</div>}
        {error && <div role="alert" className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-[12px] text-red-800">{error}</div>}
        {running && <LoadingBlock label="Replaying findings and attack paths..." />}

        {!running && !result && !error && (
          <EmptyBlock label={`Pick a scenario and run it to see how ${shortEntity(targetURN)} changes the attack graph.`} />
        )}

        {!running && result && (
          <div className="space-y-5" data-testid="attack-simulation-result">
            {!resultIsCurrent && (
              <div className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px] text-[var(--text-muted)]">
                Showing the last run ({attackSimulationScenarioFor(result.scenario)?.label ?? result.scenario} on {shortEntity(result.targetURN)}). Run again to simulate the current selection.
              </div>
            )}
            <div className="grid gap-4 md:grid-cols-3">
              <MetricCard
                label="Attack Paths"
                value={`${result.before.attackPathCount} → ${result.after.attackPathCount}`}
                detail={`${signedChange(result.attackPathCountChange)} paths`}
                intent={changeIntent(result.attackPathCountChange, attackSimulationScenarioFor(result.scenario)?.intent ?? "defend")}
              />
              <MetricCard
                label="Attack Path Score"
                value={`${result.before.totalAttackPathScore} → ${result.after.totalAttackPathScore}`}
                detail={`${signedChange(result.attackPathScoreChange)} points`}
                intent={changeIntent(result.attackPathScoreChange, attackSimulationScenarioFor(result.scenario)?.intent ?? "defend")}
              />
              <MetricCard
                label="Finding Risk"
                value={`${result.before.totalRiskScore} → ${result.after.totalRiskScore}`}
                detail={`${signedChange(result.riskScoreChange)} across ${result.after.findingCount} findings`}
                intent={changeIntent(result.riskScoreChange, attackSimulationScenarioFor(result.scenario)?.intent ?? "defend")}
              />
            </div>

            {result.graphEvidenceStatus && result.graphEvidenceStatus !== "included" && (
              <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-[12px] text-amber-800">
                The graph store was not available to this run, so attack paths were scored from findings alone.
              </div>
            )}

            <div className="grid gap-5 lg:grid-cols-2">
              <PathList title="Paths Closed" paths={result.removedPaths} empty="No attack paths close under this change." />
              <PathList title="Paths Opened" paths={result.addedPaths} empty="No new attack paths open under this change." />
            </div>
            <PathList title="Paths Still Open" paths={result.remainingPaths} empty="No attack paths remain in the replay." />

            <div>
              <h3 className="text-[12px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Findings Affected ({result.affectedFindings.length})</h3>
              {result.affectedFindings.length === 0 ? (
                <p className="mt-2 text-[13px] text-[var(--text-muted)]">No finding changes risk under this change.</p>
              ) : (
                <div className="mt-2 overflow-x-auto">
                  <table className="data-table min-w-[560px]">
                    <thead>
                      <tr><th>Finding</th><th>Risk</th><th>Why it changed</th></tr>
                    </thead>
                    <tbody>
                      {result.affectedFindings.map((impact) => (
                        <tr key={impact.findingID}>
                          <td>
                            <Link href={`/findings/${encodeURIComponent(impact.findingID)}`} prefetch={false} className="font-medium text-[var(--text-primary)] hover:underline">{impact.findingID}</Link>
                            {impact.ruleID && <div className="font-mono text-[11px] text-[var(--text-muted)]">{impact.ruleID}</div>}
                          </td>
                          <td className="whitespace-nowrap text-[13px]">{impact.before} → {impact.after}</td>
                          <td className="text-[12px] text-[var(--text-secondary)]">
                            {[...impact.removedReasons.map((reason) => `− ${reason}`), ...impact.addedReasons.map((reason) => `+ ${reason}`)].join(", ") || "Score recomputed"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}
