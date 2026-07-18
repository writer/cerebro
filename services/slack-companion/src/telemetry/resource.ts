import { arch, cpus, hostname, platform, totalmem } from "node:os";
import { memoryUsage, pid, version as nodeVersion } from "node:process";
import type { TelemetryAttributes, TelemetryOptions } from "./types.js";

export function runtimeAttributes(runtimeOptions: TelemetryOptions, processStartedAt: number): TelemetryAttributes {
  const resourceAttributes = parseResourceAttributes(runtimeOptions.resourceAttributes ?? "");
  const memory = memoryUsage();
  const serviceName = runtimeOptions.serviceName || resourceAttributes["service.name"] || "cerebro-slack-companion";
  const deploymentEnvironment = runtimeOptions.deploymentEnvironment
    || resourceAttributes["deployment.environment.name"]
    || resourceAttributes["deployment.environment"]
    || "unknown";
  const cloudRegion = runtimeOptions.cloudRegion ?? resourceAttributes["cloud.region"];
  const cloudProvider = runtimeOptions.cloudProvider ?? resourceAttributes["cloud.provider"] ?? (cloudRegion ? "aws" : "unknown");
  const hostName = hostname();
  return {
    ...resourceAttributes,
    "service.name": serviceName,
    "service.version": runtimeOptions.serviceVersion,
    "deployment.environment": deploymentEnvironment,
    "deployment.environment.name": deploymentEnvironment,
    "host.name": hostName,
    "os.type": platform(),
    "os.arch": arch(),
    "process.pid": pid,
    "process.uptime_ms": Math.max(0, Date.now() - processStartedAt),
    "process.runtime.name": "nodejs",
    "process.runtime.version": nodeVersion,
    "process.cpu.count": cpus().length,
    "process.memory.rss_bytes": memory.rss,
    "node.heap.used_bytes": memory.heapUsed,
    "node.heap.total_bytes": memory.heapTotal,
    "node.external_memory.bytes": memory.external,
    "host.memory.total_bytes": totalmem(),
    "cloud.provider": cloudProvider,
    "cloud.region": cloudRegion ?? "",
    "cloud.platform": cloudProvider === "aws" && (runtimeOptions.ecsClusterName || runtimeOptions.ecsServiceName) ? "aws_ecs" : cloudProvider,
    "aws.ecs.cluster.name": runtimeOptions.ecsClusterName ?? "",
    "aws.ecs.service.name": runtimeOptions.ecsServiceName ?? "",
    "aws.ecs.task.family": runtimeOptions.ecsTaskFamily ?? "",
    "aws.ecs.task.revision": runtimeOptions.ecsTaskRevision ?? "",
  };
}

function parseResourceAttributes(raw: string): Record<string, string> {
  const attributes: Record<string, string> = {};
  for (const part of splitResourceAttributePairs(raw)) {
    const index = firstUnescapedEquals(part);
    if (index < 1) continue;
    const key = unescapeResourceAttribute(part.slice(0, index).trim());
    const value = unescapeResourceAttribute(part.slice(index + 1).trim()).replace(/^"|"$/g, "");
    if (key && value) attributes[key] = value;
  }
  return attributes;
}

function splitResourceAttributePairs(raw: string): string[] {
  const parts: string[] = [];
  let current = "";
  let escaped = false;
  for (const char of raw) {
    if (escaped) {
      current += `\\${char}`;
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (char === ",") {
      parts.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  if (escaped) current += "\\";
  parts.push(current);
  return parts;
}

function firstUnescapedEquals(raw: string): number {
  let escaped = false;
  for (let index = 0; index < raw.length; index += 1) {
    const char = raw[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (char === "=") return index;
  }
  return -1;
}

function unescapeResourceAttribute(raw: string): string {
  let out = "";
  let escaped = false;
  for (const char of raw) {
    if (escaped) {
      out += char;
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    out += char;
  }
  if (escaped) out += "\\";
  return out;
}
