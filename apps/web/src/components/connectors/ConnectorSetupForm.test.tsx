/**
 * @vitest-environment jsdom
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import ConnectorSetupForm from "@/components/connectors/ConnectorSetupForm";
import { fetchCerebro } from "@/lib/cerebro-client";
import type { ConnectorCatalogEntry, NormalizedCredentialStore } from "@/lib/connectors";

vi.mock("@/lib/cerebro-client", () => ({
  fetchCerebro: vi.fn(),
}));

const fetchCerebroMock = vi.mocked(fetchCerebro);

const credentialStores: NormalizedCredentialStore[] = [{
  id: "environment_managed",
  label: "Environment managed",
  shortLabel: "Env",
  provider: "Deployment",
  description: "Runtime-managed credentials.",
  mode: "environment_managed",
  available: true,
  default: true,
  status: "ready",
  detail: "Ready",
  referencePrefixes: ["env:"],
  referenceNamespaceTemplate: "CEREBRO_SOURCE_<SOURCE>_*",
  referenceFieldTemplate: "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>",
  referencePlaceholder: "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>",
  nativeResolutionAvailable: false,
  setupSteps: [],
  requiredConfig: [],
}];

const awsSecretStores: NormalizedCredentialStore[] = [{
  id: "aws_secrets_manager",
  label: "AWS Secrets Manager",
  shortLabel: "ASM",
  provider: "Amazon Web Services",
  description: "Runtime-managed AWS Secrets Manager references.",
  mode: "reference",
  available: true,
  default: true,
  status: "ready",
  detail: "server-side resolver ready",
  referencePrefixes: ["env:", "aws-sm:"],
  referenceNamespaceTemplate: "cerebro/<tenant>/<source>/<runtime>/credentials",
  referenceFieldTemplate: "aws-sm:<region>:cerebro/<tenant>/<source>/<runtime>/credentials#<field>",
  referencePlaceholder: "aws-sm:us-east-1:cerebro/<tenant>/<source>/<runtime>/credentials#<field>",
  nativeResolutionAvailable: true,
  setupSteps: [],
  requiredConfig: [],
}];

const vaultCredentialStores: NormalizedCredentialStore[] = [{
  id: "cerebro_vault",
  label: "Managed credential vault",
  shortLabel: "Vault",
  provider: "Backend",
  description: "Encrypted connector credential envelopes.",
  mode: "encrypted_submission",
  available: true,
  default: true,
  status: "ready",
  detail: "Ready",
  referencePrefixes: [],
  nativeResolutionAvailable: true,
  setupSteps: [],
  requiredConfig: [],
}];

function awsConnector(): ConnectorCatalogEntry {
  return {
    source_id: "aws",
    name: "AWS",
    display_name: "Amazon Web Services",
    scope_options: [
      { id: "aws.s3_bucket", label: "S3 buckets", families: ["aws.s3_bucket"], support: "collecting" },
      { id: "aws.identity_center", label: "IAM Identity Center assignments", families: ["aws.identity_center"], support: "collecting" },
    ],
    connection_methods: [{
      id: "aws_sso_profile",
      label: "AWS IAM Identity Center profile",
      short_label: "AWS SSO",
      category: "Recommended",
      description: "Use a server-side AWS CLI SSO profile.",
      credential_stores: ["environment_managed"],
      saveable: true,
      recommended: true,
      product_groups: [
        { id: "core", label: "Core AWS inventory", families: ["aws.s3_bucket"], required: true, default_enabled: true },
        { id: "identity_center", label: "IAM Identity Center", families: ["aws.identity_center"], default_enabled: false },
      ],
    }],
  };
}

function awsExternalReferenceConnector(): ConnectorCatalogEntry {
  return {
    source_id: "aws",
    name: "AWS",
    display_name: "Amazon Web Services",
    scope_options: [],
    connection_methods: [{
      id: "external_reference",
      label: "External secret-store reference",
      short_label: "Store ref",
      category: "Reference",
      description: "Use AWS Secrets Manager references.",
      credential_stores: ["aws_secrets_manager"],
      saveable: true,
      config_fields: [
        { key: "account_id", label: "Account ID", required: true },
      ],
      credential_fields: [
        { key: "access_key_id", label: "Access key ID", required: true, reference_only: true },
        { key: "secret_access_key", label: "Secret access key", required: true, reference_only: true },
      ],
    }],
  };
}

function tokenConnector(): ConnectorCatalogEntry {
  return {
    source_id: "anthropic",
    name: "Anthropic",
    display_name: "Anthropic",
    scope_options: [],
    connection_methods: [{
      id: "encrypted_submission",
      label: "Encrypted credential submission",
      short_label: "Vault",
      category: "Managed",
      description: "Store a brokered token.",
      credential_stores: ["cerebro_vault"],
      saveable: true,
      config_fields: [],
      credential_fields: [{ key: "token", label: "Token", type: "password", required: true, secret: true }],
    }],
  };
}

describe("ConnectorSetupForm", () => {
  let container: HTMLDivElement;
  let root: Root;
  const onConnected = vi.fn();

  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    fetchCerebroMock.mockResolvedValue({ ok: true, data: {} } as never);
    onConnected.mockReset();
  });

  afterEach(() => {
    act(() => {
      root.unmount();
    });
    container.remove();
    fetchCerebroMock.mockReset();
  });

  async function renderForm(connector: ConnectorCatalogEntry, stores: NormalizedCredentialStore[] = credentialStores) {
    await act(async () => {
      root.render(
        <ConnectorSetupForm
          connector={connector}
          tenantID="writer"
          apiKey="test-key"
          credentialStores={stores}
          onConnected={onConnected}
        />,
      );
    });
  }

  it("preserves user-enabled product groups across connector metadata refreshes", async () => {
    await renderForm(awsConnector());

    const collectIdentityCenter = container.querySelector<HTMLButtonElement>("[role='switch'][aria-label='Collect IAM Identity Center']");
    expect(collectIdentityCenter).not.toBeNull();

    await act(async () => {
      collectIdentityCenter?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    });
    expect(container.querySelector("[role='switch'][aria-label='Skip IAM Identity Center']")).not.toBeNull();

    await renderForm(awsConnector());
    expect(container.querySelector("[role='switch'][aria-label='Skip IAM Identity Center']")).not.toBeNull();

    fetchCerebroMock.mockResolvedValueOnce({
      ok: true,
      data: {
        source_id: "aws",
        runtime_id: "writer-aws-connection",
        tenant_id: "writer",
        status: "ready",
        summary: "Preflight passed.",
        next_action: "save_connection",
        checks: [{ id: "source_check", label: "Source validation", status: "passed", severity: "success" }],
        scope_preview: { available_resource_types: 2, enabled_resource_types: 2, disabled_resource_types: 0, exact_resource_count: 0 },
        credential_boundary: { mode: "aws_sso_profile", credential_store_id: "environment_managed", reference_only: true },
      },
    } as never);
    const preflightButton = Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find((button) => button.textContent?.includes("Run preflight"));
    expect(preflightButton).toBeDefined();
    await act(async () => {
      preflightButton?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    });
    const preflightCall = fetchCerebroMock.mock.calls.find((call) => call[0] === "/connectors/aws/preflight");
    expect(preflightCall).toBeDefined();

    fetchCerebroMock.mockResolvedValueOnce({
      ok: true,
      data: {
        source_id: "aws",
        runtime: { id: "runtime-from-response", source_id: "aws", tenant_id: "writer" },
        credential: {
          id: "cred_aws",
          tenant_id: "writer",
          source_id: "aws",
          runtime_id: "runtime-from-response",
          credential_store_id: "environment_managed",
          auth_method: "aws_sso_profile",
          status: "valid",
          key_id: "environment",
          fields: [],
        },
      },
    } as never);
    const form = container.querySelector("form");
    expect(form).not.toBeNull();
    await act(async () => {
      form?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });

    const connectionCall = fetchCerebroMock.mock.calls.find((call) => call[0] === "/connectors/aws/connections");
    expect(connectionCall).toBeDefined();
    const payload = JSON.parse(String(connectionCall?.[2]?.body ?? "{}"));
    expect(payload.scope_policy?.excluded_families ?? []).not.toContain("aws.identity_center");
    expect(onConnected).toHaveBeenCalledWith(expect.objectContaining({
      sourceID: "aws",
      tenantID: "writer",
      runtimeID: "runtime-from-response",
    }));
  });

  it("applies generated AWS Secrets Manager references to credential fields", async () => {
    await renderForm(awsExternalReferenceConnector(), awsSecretStores);

    const applyButton = Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find((button) => button.textContent?.includes("Apply references"));
    expect(applyButton).toBeDefined();

    await act(async () => {
      applyButton?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    });

    const accessKeyInput = container.querySelector<HTMLInputElement>('input[name="credential:access_key_id"]');
    const secretKeyInput = container.querySelector<HTMLInputElement>('input[name="credential:secret_access_key"]');

    expect(accessKeyInput?.value).toBe("aws-sm:us-east-1:cerebro/writer/aws/writer-aws-connection/credentials#access_key_id");
    expect(secretKeyInput?.value).toBe("aws-sm:us-east-1:cerebro/writer/aws/writer-aws-connection/credentials#secret_access_key");
  });

  it("lists stored managed vault credentials and revokes the selected record", async () => {
    fetchCerebroMock.mockImplementation(async (path: string) => {
      if (path === "/connectors/anthropic/credentials?tenant_id=writer&runtime_id=writer-anthropic-connection") {
        return {
          ok: true,
          status: 200,
          data: {
            source_id: "anthropic",
            tenant_id: "writer",
            runtime_id: "writer-anthropic-connection",
            credentials: [{
              id: "cred_1234567890",
              tenant_id: "writer",
              source_id: "anthropic",
              runtime_id: "writer-anthropic-connection",
              credential_store_id: "cerebro_vault",
              auth_method: "encrypted_submission",
              status: "valid",
              key_id: "connector-vault-test",
              fields: ["token"],
              updated_at: "2026-06-15T12:00:00Z",
            }],
          },
        } as never;
      }
      return { ok: true, status: 200, data: {} } as never;
    });

    await renderForm(tokenConnector(), vaultCredentialStores);
    await act(async () => {
      await new Promise((resolve) => window.setTimeout(resolve, 0));
    });

    expect(container.textContent).toContain("Credential broker");
    expect(container.textContent).toContain("Valid");

    const revokeButton = Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find((button) => button.textContent?.includes("Revoke"));
    expect(revokeButton).toBeDefined();
    await act(async () => {
      revokeButton?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      await new Promise((resolve) => window.setTimeout(resolve, 0));
    });

    expect(fetchCerebroMock.mock.calls.some((call) => call[0] === "/connectors/anthropic/credentials/cred_1234567890/revoke")).toBe(true);
  });
});
