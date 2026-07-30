import childProcess from "node:child_process";
import dgram from "node:dgram";
import dns from "node:dns";
import dnsPromises from "node:dns/promises";
import http from "node:http";
import http2 from "node:http2";
import https from "node:https";
import { syncBuiltinESMExports } from "node:module";
import net from "node:net";
import tls from "node:tls";

const OFFLINE_ERROR_CODE = "CEREBRO_OFFLINE_ACCESS_DENIED";

export interface SlackWorkingStateOfflineExecutionV1 {
  readonly child_process_access: "denied";
  readonly filesystem_write_access: "denied";
  readonly native_addon_access: "denied";
  readonly network_access: "denied";
  readonly network_probe: "passed";
  readonly schema_version: "slack-working-state-offline-execution/v1";
  readonly worker_access: "denied";
}

interface PermissionApi {
  has(scope: string, reference?: string): boolean;
}

export class OfflineHarnessAccessError extends Error {
  readonly code = OFFLINE_ERROR_CODE;

  constructor(resource: string) {
    super(`Offline hillclimb denied ${resource}.`);
    this.name = "OfflineHarnessAccessError";
  }
}

export function installOfflineNetworkGuard(): void {
  const deny = (resource: string) =>
    function denyOfflineAccess(): never {
      throw new OfflineHarnessAccessError(resource);
    };
  const replace = (
    target: object,
    property: string,
    resource: string,
  ): void => {
    Object.defineProperty(target, property, {
      configurable: true,
      value: deny(resource),
      writable: true,
    });
  };

  for (const property of ["lookup", "lookupService", "resolve", "resolve4",
    "resolve6", "resolveAny", "resolveCaa", "resolveCname", "resolveMx",
    "resolveNaptr", "resolveNs", "resolvePtr", "resolveSoa", "resolveSrv",
    "resolveTxt", "reverse"]) {
    replace(dns, property, `DNS ${property}`);
    replace(dnsPromises, property, `DNS promises ${property}`);
  }
  for (const resolver of [
    dns.Resolver.prototype,
    dnsPromises.Resolver.prototype,
  ]) {
    for (const property of ["resolve", "resolve4", "resolve6", "resolveAny",
      "resolveCaa", "resolveCname", "resolveMx", "resolveNaptr", "resolveNs",
      "resolvePtr", "resolveSoa", "resolveSrv", "resolveTxt", "reverse"]) {
      replace(resolver, property, `DNS resolver ${property}`);
    }
  }
  for (const property of ["connect", "createConnection", "createServer"]) {
    replace(net, property, `network ${property}`);
  }
  replace(net.Socket.prototype, "connect", "socket connection");
  replace(net.Server.prototype, "listen", "network listener");

  for (const property of ["connect", "createServer"]) {
    replace(tls, property, `TLS ${property}`);
  }
  replace(tls.TLSSocket.prototype, "connect", "TLS socket connection");
  replace(dgram, "createSocket", "datagram socket");

  for (const [target, label] of [
    [http, "HTTP"],
    [https, "HTTPS"],
  ] as const) {
    for (const property of ["get", "request", "createServer"]) {
      replace(target, property, `${label} ${property}`);
    }
  }
  for (const property of ["connect", "createServer", "createSecureServer"]) {
    replace(http2, property, `HTTP/2 ${property}`);
  }

  replace(childProcess, "exec", "child process");
  replace(childProcess, "execFile", "child process");
  replace(childProcess, "fork", "child process");
  replace(childProcess, "spawn", "child process");

  replace(globalThis, "fetch", "fetch");
  if ("WebSocket" in globalThis) {
    replace(globalThis, "WebSocket", "WebSocket");
  }
  if ("EventSource" in globalThis) {
    replace(globalThis, "EventSource", "EventSource");
  }
  syncBuiltinESMExports();
}

export async function proveOfflineExecution():
  Promise<SlackWorkingStateOfflineExecutionV1> {
  const permission = (process as typeof process & {
    permission?: PermissionApi;
  }).permission;
  if (permission === undefined) {
    throw new Error("Offline hillclimb requires the Node permission model.");
  }
  for (const [scope, label] of [
    ["child", "child processes"],
    ["worker", "workers"],
    ["addons", "native addons"],
  ] as const) {
    if (permission.has(scope)) {
      throw new Error(`Offline hillclimb must deny ${label}.`);
    }
  }
  if (permission.has("fs.write", process.cwd())) {
    throw new Error("Offline hillclimb must deny filesystem writes.");
  }

  await Promise.all([
    expectOfflineDenial("fetch", () =>
      fetch("https://offline-probe.invalid/")),
    expectOfflineDenial("DNS", () =>
      dnsPromises.lookup("offline-probe.invalid")),
    expectOfflineDenial("TCP", () =>
      net.connect(443, "offline-probe.invalid")),
    expectOfflineDenial("TLS", () =>
      tls.connect(443, "offline-probe.invalid")),
    expectOfflineDenial("HTTP", () =>
      http.get("http://offline-probe.invalid/")),
    expectOfflineDenial("HTTPS", () =>
      https.get("https://offline-probe.invalid/")),
    expectOfflineDenial("HTTP/2", () =>
      http2.connect("https://offline-probe.invalid/")),
    expectOfflineDenial("datagram", () =>
      dgram.createSocket("udp4")),
    expectOfflineDenial("child process", () =>
      childProcess.spawn(process.execPath, ["--version"])),
  ]);

  return Object.freeze({
    child_process_access: "denied",
    filesystem_write_access: "denied",
    native_addon_access: "denied",
    network_access: "denied",
    network_probe: "passed",
    schema_version: "slack-working-state-offline-execution/v1",
    worker_access: "denied",
  });
}

async function expectOfflineDenial(
  label: string,
  operation: () => unknown,
): Promise<void> {
  let probeError: unknown;
  try {
    await operation();
  } catch (error) {
    probeError = error;
  }
  if (
    !(probeError instanceof OfflineHarnessAccessError)
    || probeError.code !== OFFLINE_ERROR_CODE
  ) {
    throw new Error(`Offline hillclimb ${label} denial probe failed.`);
  }
}
