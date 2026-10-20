import { describe, expect, it } from "vitest";

import {
  sourceCredentialHealth,
  type CredentialStoreBinding,
  type CredentialStoreIssue,
  type CredentialStoreListResponse,
  type CredentialStoreOperational,
} from "@/lib/credential-stores";

const store = (
  id: string,
  label: string,
  bindings: CredentialStoreBinding[] = [],
  issues: CredentialStoreIssue[] = [],
): CredentialStoreOperational => ({
  bindings,
  health: { status: "in_use" },
  issues,
  store: { available: true, id, label, mode: "encrypted_submission", provider: "Cerebro" },
  usage: { bindings: bindings.length, connections: bindings.length, credentials: 0, field_references: 0, issues: issues.length },
});

const binding = (overrides: Partial<CredentialStoreBinding>): CredentialStoreBinding => ({
  credential_store_id: "cerebro_vault",
  id: `${overrides.source_id}-${overrides.runtime_id ?? "runtime"}`,
  ...overrides,
});

const response = (stores: CredentialStoreOperational[], issues: CredentialStoreIssue[] = []): CredentialStoreListResponse => ({
  credential_store_status: "ready",
  generated_at: "2026-01-15T12:00:00Z",
  issues,
  runtime_store_status: "ready",
  stores,
});

describe("sourceCredentialHealth", () => {
  it("reports a validated credential as valid with its store and check time", () => {
    const health = sourceCredentialHealth(response([
      store("cerebro_vault", "Managed vault", [
        binding({ credential_id: "cred-okta", credential_status: "valid", last_validated_at: "2026-01-15T11:00:00Z", source_id: "okta" }),
      ]),
    ]));

    expect(health.get("okta")).toEqual({
      issues: 0,
      lastValidatedAt: "2026-01-15T11:00:00Z",
      referenceOnly: false,
      state: "ok",
      stores: ["Managed vault"],
    });
  });

  it("marks revoked or invalid credentials as failing", () => {
    const health = sourceCredentialHealth(response([
      store("cerebro_vault", "Managed vault", [binding({ credential_status: "revoked", source_id: "github" })]),
    ]));

    expect(health.get("github")).toMatchObject({ detail: "Credential is revoked.", state: "failing" });
  });

  it("lets a blocking issue outrank a warning and keeps its detail", () => {
    const health = sourceCredentialHealth(response([
      store("cerebro_vault", "Managed vault", [binding({ source_id: "aws" })], [
        { detail: "Not validated yet.", id: "warn", severity: "warning", source_id: "aws", status: "warning" },
        { detail: "Referenced credential is missing.", id: "block", severity: "error", source_id: "aws", status: "blocked" },
      ]),
    ]));

    expect(health.get("aws")).toMatchObject({ detail: "Referenced credential is missing.", issues: 2, state: "failing" });
  });

  it("counts an issue reported both at top level and on its store once", () => {
    const issue: CredentialStoreIssue = { detail: "Not validated yet.", id: "same", severity: "warning", source_id: "aws", status: "warning" };
    const health = sourceCredentialHealth(response([store("cerebro_vault", "Managed vault", [], [issue])], [issue]));

    expect(health.get("aws")?.issues).toBe(1);
  });

  // An optional resolver nobody has set up is not a problem with any integration.
  it("ignores store-level issues that name no source", () => {
    const health = sourceCredentialHealth(response([
      store("external_reference", "External references", [], [
        { detail: "Resolver not configured.", id: "resolver", severity: "warning", status: "warning" },
      ]),
    ]));

    expect(health.size).toBe(0);
  });

  it("flags sources whose secrets all live outside Cerebro as reference-only", () => {
    const health = sourceCredentialHealth(response([
      store("environment_managed", "Environment", [binding({ credential_status: "reference_only", source_id: "aws" })]),
    ]));

    expect(health.get("aws")).toMatchObject({ referenceOnly: true, state: "ok" });
  });

  it("uses the oldest check across runtimes and lists every store once", () => {
    const health = sourceCredentialHealth(response([
      store("cerebro_vault", "Managed vault", [
        binding({ last_validated_at: "2026-01-15T11:00:00Z", runtime_id: "a", source_id: "okta" }),
        binding({ last_validated_at: "2026-01-10T11:00:00Z", runtime_id: "b", source_id: "okta" }),
      ]),
      store("environment_managed", "Environment", [binding({ runtime_id: "c", source_id: "okta" })]),
    ]));

    expect(health.get("okta")).toMatchObject({
      lastValidatedAt: "2026-01-10T11:00:00Z",
      stores: ["Managed vault", "Environment"],
    });
  });
});
