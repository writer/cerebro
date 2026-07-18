export function cleanTelemetryName(value: string): string {
  return compactKeyPart(value).replace(/_/g, ".");
}

export function boundedKeyPart(value: string): string {
  const cleaned = compactKeyPart(value);
  return cleaned.length > 64 ? cleaned.slice(0, 64) : cleaned || "unknown";
}

export function compactKeyPart(value: string): string {
  const normalized = value.trim()
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^a-zA-Z0-9_.-]+/g, "_")
    .replace(/[.-]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toLowerCase();
  return normalized || "unknown";
}

export function componentFromSpanName(name: string): string {
  return name.split(".")[0] ?? "unknown";
}
