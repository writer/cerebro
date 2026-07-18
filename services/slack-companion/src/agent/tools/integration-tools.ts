import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { EvidenceCasClient } from "../../evidence-cas/client.js";
import { InfisicalClient } from "../../infisical/client.js";
import type { SecurityToolDeps } from "./types.js";
import { safeToolResult } from "./tool-result.js";

export function createIntegrationTools(deps: SecurityToolDeps): AgentTool[] {
  const infisical = deps.infisical ?? new InfisicalClient(deps.config);
  const evidenceCas = new EvidenceCasClient(deps.config, {
    readTokenProviderName: "infisical",
    readTokenProvider: async () => {
      const secretName = deps.config.evidenceCas.readTokenInfisicalSecretName;
      if (!secretName) return undefined;
      return infisical.secretValueForRuntime(
        { secretName },
        { requireAllowSecretValues: false },
      );
    },
  });
  const evidenceCasStatusParams = Type.Object({});
  const evidenceCasResolveParams = Type.Object({
    uri: Type.Optional(Type.String()),
    bucket: Type.Optional(Type.String()),
    key: Type.Optional(Type.String()),
    digest: Type.Optional(Type.String()),
    verify: Type.Optional(Type.Boolean()),
  });
  const infisicalStatusParams = Type.Object({
    check_connection: Type.Optional(Type.Boolean()),
  });
  const infisicalSecretParams = Type.Object({
    secret_name: Type.String(),
    environment: Type.Optional(Type.String()),
    secret_path: Type.Optional(Type.String()),
    include_imports: Type.Optional(Type.Boolean()),
  });

  return [
    {
      name: "evidence_cas_status",
      label: "EvidenceCAS status",
      description: "Check whether the EvidenceCAS content-addressed evidence plane is configured and reachable. Use when CAS manifest, digest, or chain-of-custody evidence is needed.",
      parameters: evidenceCasStatusParams,
      execute: async () => safeToolResult(async () => evidenceCas.status()),
    },
    {
      name: "evidence_cas_resolve",
      label: "EvidenceCAS resolve",
      description: "Resolve and optionally verify one EvidenceCAS manifest ref surfaced by Cerebro evidence. Read-only. Use for raw evidence, digest, manifest, artifact integrity, or chain-of-custody questions; do not use it as a finding search database.",
      parameters: evidenceCasResolveParams,
      execute: async (_toolCallId, params) => {
        const args = params as { uri?: string; bucket?: string; key?: string; digest?: string; verify?: boolean };
        return safeToolResult(async () => evidenceCas.resolve({
          uri: args.uri,
          bucket: args.bucket,
          key: args.key,
          digest: args.digest,
          verify: args.verify,
        }));
      },
    },
    {
      name: "infisical_status",
      label: "Infisical status",
      description: "Check whether Cerebro's Infisical AWS-auth runtime access is configured. With check_connection=true, performs AWS auth login only; it never returns secret values.",
      parameters: infisicalStatusParams,
      execute: async (_toolCallId, params) => {
        const args = params as { check_connection?: boolean };
        return safeToolResult(async () => infisical.status({ checkConnection: args.check_connection }));
      },
    },
    {
      name: "infisical_secret_metadata",
      label: "Infisical secret metadata",
      description: "Read non-value metadata for one Infisical secret by name: presence, version, path, timestamps, tags, rotation metadata, and actor. Does not request or return the secret value.",
      parameters: infisicalSecretParams,
      execute: async (_toolCallId, params) => {
        const args = params as { secret_name: string; environment?: string; secret_path?: string; include_imports?: boolean };
        return safeToolResult(async () => infisical.secretMetadata({
          secretName: args.secret_name,
          environment: args.environment,
          secretPath: args.secret_path,
          includeImports: args.include_imports,
        }));
      },
    },
    {
      name: "infisical_secret_fingerprint",
      label: "Infisical secret fingerprint",
      description: "Fetch one Infisical secret value only inside the tool process and return length plus a short SHA-256 prefix for rotation or mirror comparison. Never returns the raw value.",
      parameters: infisicalSecretParams,
      execute: async (_toolCallId, params) => {
        const args = params as { secret_name: string; environment?: string; secret_path?: string; include_imports?: boolean };
        return safeToolResult(async () => infisical.secretFingerprint({
          secretName: args.secret_name,
          environment: args.environment,
          secretPath: args.secret_path,
          includeImports: args.include_imports,
        }));
      },
    },
  ];
}
