import { boundedKeyPart } from "./names.js";

export class MetricsRegistry {
  private readonly counters = new Map<string, number>();
  private readonly gauges = new Map<string, number>();
  private enabled = false;

  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  add(name: string, labels: Record<string, string | number | boolean | undefined>, value: number): void {
    if (!this.enabled || !name.trim() || !Number.isFinite(value)) return;
    const key = metricKey(name, labels);
    this.counters.set(key, (this.counters.get(key) ?? 0) + value);
  }

  set(name: string, labels: Record<string, string | number | boolean | undefined>, value: number): void {
    if (!this.enabled || !name.trim() || !Number.isFinite(value)) return;
    const key = metricKey(name, labels);
    this.gauges.set(key, value);
  }

  render(): string {
    if (!this.enabled) return "";
    const lines = [...this.counters.entries(), ...this.gauges.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, value]) => `${key} ${value}`);
    return lines.length > 0 ? `${lines.join("\n")}\n` : "";
  }

  clear(): void {
    this.counters.clear();
    this.gauges.clear();
    this.enabled = false;
  }
}

export const registry = new MetricsRegistry();

export function normalizeLabelValue(value: unknown): string {
  return boundedKeyPart(String(value ?? "unknown"));
}

function metricKey(name: string, labels: Record<string, string | number | boolean | undefined>): string {
  const cleanName = name.replace(/[^a-zA-Z0-9_:]/g, "_");
  const entries = Object.entries(labels)
    .filter(([, value]) => value !== undefined)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key.replace(/[^a-zA-Z0-9_]/g, "_")}="${escapeMetricLabel(normalizeLabelValue(value))}"`);
  return entries.length ? `${cleanName}{${entries.join(",")}}` : cleanName;
}

function escapeMetricLabel(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, "\\\"");
}
