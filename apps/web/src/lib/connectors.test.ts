import { describe, expect, it } from "vitest";

import {
  connectionMethodsForConnector,
  connectorAccessStatusLabel,
  connectorCatalogStatusLabel,
  connectorCredentialHealth,
  connectorCredentialPath,
  connectorCredentialRevokePath,
  connectorCredentialRotatePath,
  connectorCredentialsPath,
  connectorCredentialStatusLabel,
  connectorConnectedContextFromResponse,
  connectorDefinitionOriginLabel,
  connectorDepositsPath,
  connectorDefinitionBlockingChecks,
  connectorDefinitionNextStage,
  connectorDefinitionStatus,
  connectorDiagnosticStageLabel,
  connectorDiagnosticStatusLabel,
  connectorDisplayMetadata,
  sourceActivationPlanCategoryCounts,
  sourceActivationPlanPath,
  sourceActivationPlanStatusLabel,
  sourceRuntimeSyncPath,
  connectorIntegrationDepthLabel,
  connectorIsCatalogOnly,
  connectorMatchesSlug,
  connectorReadinessStageLabel,
  connectorRequestActionLabel,
  connectorRuntimeSurfaceLabel,
  connectorSearchText,
  connectorSetupAllowed,
  connectorScopeOptionFamilies,
  connectorSubmitErrorMessage,
  defaultConnectorDefinitionDraft,
  defaultCredentialStoreID,
  encryptConnectorCredentials,
  normalizeCredentialStores,
  normalizeScopePolicy,
  scopePolicyExclusionCount,
} from "./connectors";
import type { ConnectorDefinition } from "./connectors";

describe("connector diagnostic timeline labels", () => {
  it("labels provider-neutral diagnostic stages", () => {
    expect(connectorDiagnosticStageLabel("setup")).toBe("Setup");
    expect(connectorDiagnosticStageLabel("preflight")).toBe("Preflight");
    expect(connectorDiagnosticStageLabel("source_sync")).toBe("Source sync");
    expect(connectorDiagnosticStageLabel("contract_probe")).toBe("Contract probe");
    expect(connectorDiagnosticStageLabel("graph_projection")).toBe("Graph projection");
    expect(connectorDiagnosticStageLabel("finding_evaluation")).toBe("Finding evaluation");
    expect(connectorDiagnosticStageLabel("custom_stage")).toBe("custom_stage");
  });

  it("labels diagnostic status values without provider assumptions", () => {
    expect(connectorDiagnosticStatusLabel("success")).toBe("Healthy");
    expect(connectorDiagnosticStatusLabel("warning")).toBe("Needs attention");
    expect(connectorDiagnosticStatusLabel("failed")).toBe("Failed");
    expect(connectorDiagnosticStatusLabel("running")).toBe("Running");
    expect(connectorDiagnosticStatusLabel("pending")).toBe("Pending");
    expect(connectorDiagnosticStatusLabel()).toBe("Unknown");
  });
});

describe("connector credential store normalization", () => {
  it("derives a ready Cerebro vault from legacy catalog metadata", () => {
    const stores = normalizeCredentialStores({
      credential_transport: { available: true, algorithm: "RSA-OAEP-256+A256GCM", key_url: "/connectors/credential-key" },
      credential_vault: { available: true },
    });

    expect(defaultCredentialStoreID(stores)).toBe("cerebro_vault");
    expect(stores.find((store) => store.id === "cerebro_vault")).toMatchObject({
      available: true,
      detail: "Ready",
      mode: "encrypted_submission",
    });
    expect(stores.find((store) => store.id === "google_secret_manager")?.available).toBe(false);
  });

  it("only honors advertised closed-set stores and sanitizes detail copy", () => {
    const stores = normalizeCredentialStores({
      credential_stores: [
        {
          id: "aws_secrets_manager",
          label: "AWS Secrets Manager",
          provider: "Amazon Web Services",
          available: true,
          default: true,
          mode: "reference",
          detail: "deployment managed",
          status: "ready",
          reference_prefixes: ["env:", "aws-sm:"],
          reference_namespace_template: "cerebro/<tenant>/<source>/<runtime>/credentials",
          reference_field_template: "aws-sm:<region>:cerebro/<tenant>/<source>/<runtime>/credentials#<field>",
          reference_placeholder: "aws-sm:us-east-1:cerebro/tenant-a/aws/runtime-a/credentials#token",
          native_resolution_available: true,
          required_config: [{ env: "CEREBRO_CONNECTOR_SECRET_STORES", label: "Enabled stores", required: true }],
        },
        { id: "unknown_store", available: true, detail: "should not render" },
      ],
    });

    expect(defaultCredentialStoreID(stores)).toBe("aws_secrets_manager");
    expect(stores.find((store) => store.id === "aws_secrets_manager")).toMatchObject({
      available: true,
      detail: "Configured by deployment",
      mode: "reference",
      status: "ready",
      referencePrefixes: ["env:", "aws-sm:"],
      referenceNamespaceTemplate: "cerebro/<tenant>/<source>/<runtime>/credentials",
      referenceFieldTemplate: "aws-sm:<region>:cerebro/<tenant>/<source>/<runtime>/credentials#<field>",
      referencePlaceholder: "aws-sm:us-east-1:cerebro/tenant-a/aws/runtime-a/credentials#token",
      nativeResolutionAvailable: true,
    });
    expect(stores.find((store) => store.id === "aws_secrets_manager")?.requiredConfig).toHaveLength(1);
    expect(stores.some((store) => String(store.id) === "unknown_store")).toBe(false);
  });

  it("uses backend-advertised connection methods and field metadata", () => {
    const stores = normalizeCredentialStores({
      credential_stores: [
        { id: "environment_managed", label: "Environment managed", provider: "Deployment", available: true, mode: "environment_managed", detail: "ready" },
      ],
    });

    const methods = connectionMethodsForConnector({
      source_id: "aws",
      name: "AWS",
      display_name: "Amazon Web Services",
      connection_methods: [{
        id: "aws_sso_profile",
        label: "AWS IAM Identity Center profile",
        short_label: "AWS SSO",
        category: "Recommended",
        description: "Use a server-side AWS CLI SSO profile.",
        credential_stores: ["environment_managed"],
        recommended: true,
        saveable: true,
        config_fields: [
          { key: "account_id", label: "Account ID", required: true },
          { key: "profile", label: "Profile", required: true },
        ],
        prerequisites: [{ id: "aws_role", label: "Role ready", required: true }],
        steps: [{ id: "validate", label: "Validate", description: "Check access", commands: ["aws sts get-caller-identity --profile cerebro"] }],
        product_groups: [{ id: "identity_center", label: "IAM Identity Center", families: ["identity_center_account_assignment"] }],
        deployment_guides: [{ id: "trust", label: "Trust policy", language: "json", body: "{}" }],
        region_guidance: { default_region: "us-east-1", supports_global: true },
        security_notes: ["No AWS secret key is returned."],
      }],
    }, stores);

    expect(methods).toHaveLength(1);
    expect(methods[0]).toMatchObject({
      id: "aws_sso_profile",
      shortLabel: "AWS SSO",
      category: "Recommended",
      recommended: true,
      status: "guided",
      saveable: true,
    });
    expect(methods[0].config_fields?.map((field) => field.key)).toEqual(["account_id", "profile"]);
    expect(methods[0].steps[0]).toMatchObject({ id: "validate", commands: ["aws sts get-caller-identity --profile cerebro"] });
    expect(methods[0].commands).toEqual(["aws sts get-caller-identity --profile cerebro"]);
    expect(methods[0].product_groups[0]).toMatchObject({ id: "identity_center" });
    expect(methods[0].deployment_guides[0]).toMatchObject({ id: "trust" });
    expect(methods[0].region_guidance?.supports_global).toBe(true);
    expect(methods[0].security_notes).toEqual(["No AWS secret key is returned."]);
  });
});

describe("connector catalog metadata", () => {
  it("labels catalog-only executable definitions without advertising live setup", () => {
    const connector = {
      source_id: "auth0",
      name: "Auth0",
      catalog_status: "generateable",
      catalog_schema_version: "cerebro.integration/v1",
      catalog_source_path: "catalog/identity.yaml",
      definition_origin: "builtin_catalog",
      readiness_stage: "sourcegen_ready",
      integration_depth: { level: "ready", score: 68, resource_families: 2, coverage_dimensions: 4 },
      access_status: "catalog_only",
      access_reason: "Catalog definition is sourcegen-ready, but setup is not enabled by this API.",
      setup_allowed: false,
      requestable: true,
      requestable_reason: "Catalog definition is sourcegen-ready, but setup is not enabled by this API.",
      request_access_action: "Request connector",
      runtime_executable: true,
      auth_model: "oauth_client_credentials",
      verification_endpoint: "/users",
      priority_tier: "urgent",
      priority_reasons: ["identity_family"],
      missing_families: ["user_roles"],
      provider_api_status: "mapped",
      provider_api_auth_mechanics: "oauth scopes",
      provider_api_spec_url: "auth0-provider-api-spec",
      provider_api_proof_gaps: ["runtime_fixture_missing"],
      catalog_categories: ["identity"],
      resource_families: [
        {
          id: "users",
          label: "Users",
          path: "/users",
          method: "GET",
          record_selector: "$.users[*]",
          id_field: "id",
          event_kind: "auth0.users",
          schema_ref: "auth0/users/v1",
          projection_template: "identity_user",
          high_value: true,
          coverage: [{
            id: "auth0.users.identity",
            type: "app_entitlement",
            title: "User entitlements",
            support: "supported",
            evidence_types: ["identity_configuration"],
            control_domains: ["identity_and_access"],
            control_refs: [{ framework_name: "SOC 2", control_id: "CC6.1" }],
          }],
        },
        {
          id: "roles",
          label: "Roles",
          path: "/roles",
          event: { kind: "auth0.roles", schema_ref: "auth0/roles/v1" },
          projection: { template: "identity_group", fields: { name: "$.name" } },
          high_value: true,
        },
      ],
      scope_options: [{
        id: "auth0.users.identity",
        label: "User entitlements",
        type: "app_entitlement",
        support: "supported",
        evidence_types: ["identity_configuration"],
        control_refs: [{ framework_name: "SOC 2", control_id: "CC6.1" }],
      }],
    };

    expect(connectorCatalogStatusLabel(connector.catalog_status)).toBe("Runtime ready");
    expect(connectorAccessStatusLabel(connector.access_status)).toBe("Catalog only");
    expect(connectorReadinessStageLabel(connector.readiness_stage)).toBe("Runtime ready");
    expect(connectorDefinitionOriginLabel(connector.definition_origin)).toBe("Built-in catalog");
    expect(connectorIntegrationDepthLabel(connector)).toBe("Ready · 68/100");
    expect(connectorRequestActionLabel(connector)).toBe("Request connector");
    expect(connectorSetupAllowed(connector)).toBe(false);
    expect(connectorIsCatalogOnly(connector)).toBe(true);
    expect(connectorRuntimeSurfaceLabel(connector)).toBe("Runtime ready");
    expect(connectorDisplayMetadata(connector)).toMatchObject({
      category: "Identity and access",
      provider: "Auth0",
    });
    expect(connectorSearchText(connector)).toContain("oauth_client_credentials");
    expect(connectorSearchText(connector)).toContain("/roles");
    expect(connectorSearchText(connector)).toContain("get");
    expect(connectorSearchText(connector)).toContain("$.users[*]");
    expect(connectorSearchText(connector)).toContain("auth0/roles/v1");
    expect(connectorSearchText(connector)).toContain("identity_user");
    expect(connectorSearchText(connector)).toContain("identity_group");
    expect(connectorSearchText(connector)).toContain("sourcegen-ready");
    expect(connectorSearchText(connector)).toContain("catalog/identity.yaml");
    expect(connectorSearchText(connector)).toContain("identity_configuration");
    expect(connectorSearchText(connector)).toContain("soc 2 cc6.1");
    expect(connectorSearchText(connector)).toContain("runtime_fixture_missing");
    expect(connectorSearchText(connector)).toContain("user_roles");
    expect(connectorSearchText(connector)).toContain("oauth scopes");
  });

  it("treats advertised connection methods as a live runtime surface", () => {
    expect(connectorIsCatalogOnly({
      catalog_status: "generateable",
      connection_methods: [{ id: "encrypted_submission" }],
    })).toBe(false);
    expect(connectorRuntimeSurfaceLabel({
      catalog_status: "generateable",
      runtime_executable: true,
      connection_methods: [{ id: "encrypted_submission" }],
    })).toBe("Runtime supported");
  });

  it("treats restricted connector setup as inspectable metadata", () => {
    const connector = {
      source_id: "aws",
      name: "AWS",
      display_name: "Amazon Web Services",
      catalog_status: "generateable",
      access_status: "restricted",
      access_reason: "limited preview",
      readiness_stage: "api_restricted",
      integration_depth: { level: "deep", score: 84 },
      setup_allowed: false,
      requestable: true,
      requestable_reason: "limited preview",
      request_access_action: "Request in Access Hub",
      request_access_url: "https://access.example.com/request?source=aws",
      runtime_executable: true,
      connection_methods: [{ id: "encrypted_submission" }],
    };

    expect(connectorAccessStatusLabel(connector.access_status)).toBe("Restricted");
    expect(connectorReadinessStageLabel(connector.readiness_stage)).toBe("API restricted");
    expect(connectorRequestActionLabel(connector)).toBe("Request in Access Hub");
    expect(connectorSetupAllowed(connector)).toBe(false);
    expect(connectorRuntimeSurfaceLabel(connector)).toBe("Restricted");
    expect(connectorSearchText(connector)).toContain("limited preview");
  });

  it("matches friendly slugs for catalog sources with punctuation or spaces", () => {
    const connector = {
      source_id: "microsoft_365",
      name: "Microsoft 365",
      display_name: "Microsoft 365",
    };

    expect(connectorMatchesSlug(connector, "microsoft-365")).toBe(true);
    expect(connectorMatchesSlug(connector, "microsoft_365")).toBe(true);
  });
});

describe("connector credential transport", () => {
  it("rejects unsupported credential key metadata before encryption", async () => {
    await expect(encryptConnectorCredentials({
      key_id: "connector-transit-example",
      algorithm: "RSA-OAEP-256",
      jwk: { kty: "RSA", alg: "RSA-OAEP-256", n: "abc", e: "AQAB" },
    }, { token: "value" })).rejects.toThrow("algorithm");
  });

  it("uses sanitized submit errors", () => {
    expect(connectorSubmitErrorMessage(400)).not.toContain("token");
    expect(connectorSubmitErrorMessage(503)).toContain("unavailable");
  });

  it("builds credential lifecycle paths and labels statuses", () => {
    expect(connectorCredentialsPath("aws", { tenantID: "tenant-a", runtimeID: "runtime-a" })).toBe("/connectors/aws/credentials?tenant_id=tenant-a&runtime_id=runtime-a");
    expect(connectorCredentialPath("aws", "cred_123")).toBe("/connectors/aws/credentials/cred_123");
    expect(connectorCredentialRotatePath("aws", "cred_123")).toBe("/connectors/aws/credentials/cred_123/rotate");
    expect(connectorCredentialRevokePath("aws", "cred_123")).toBe("/connectors/aws/credentials/cred_123/revoke");
    expect(connectorDepositsPath("custom source")).toBe("/connectors/custom%20source/deposits");
    expect(sourceRuntimeSyncPath("runtime a", 1)).toBe("/source-runtimes/runtime%20a/sync?page_limit=1");
    expect(connectorCredentialStatusLabel("valid")).toBe("Valid");
    expect(connectorCredentialHealth({ status: "valid" })).toBe("healthy");
    expect(connectorCredentialHealth({ status: "revoked" })).toBe("bad");
  });

  it("derives connected runtime context from save responses", () => {
    expect(connectorConnectedContextFromResponse({
      source_id: "aws",
      runtime: { id: "runtime-from-runtime", tenant_id: "tenant-a" },
      credential: {
        id: "cred-1",
        tenant_id: "tenant-b",
        source_id: "aws",
        runtime_id: "runtime-from-credential",
        credential_store_id: "environment_managed",
        auth_method: "environment_managed",
        status: "valid",
        key_id: "environment",
        fields: [],
      },
    }, { sourceID: "fallback", tenantID: "tenant-c", runtimeID: "runtime-fallback" })).toMatchObject({
      sourceID: "aws",
      tenantID: "tenant-b",
      runtimeID: "runtime-from-credential",
    });
  });
});

describe("connector resource scope policy", () => {
  it("normalizes exclusions into the backend scope policy shape", () => {
    const policy = normalizeScopePolicy({
      excluded_families: [" AWS.S3_BUCKET ", "aws.s3_bucket", "gcp.storage_bucket"],
      excluded_asset_classes: [" aws.iam_role "],
      excluded_kinds: ["AWS.S3_BUCKET"],
      excluded_resource_urns: [" urn:cerebro:tenant:aws_s3_bucket:Example ", "urn:cerebro:tenant:aws_s3_bucket:Example"],
      excluded_resources: [
        { type: " AWS.S3_BUCKET ", id: " bucket-a ", reason: " duplicate test " },
        { urn: " urn:cerebro:tenant:gcp_project:project-a " },
        { type: "   ", id: "ignored" },
      ],
    });

    expect(policy).toEqual({
      mode: "exclude",
      excluded_families: ["aws.s3_bucket", "gcp.storage_bucket"],
      excluded_asset_classes: ["aws.iam_role"],
      excluded_kinds: ["aws.s3_bucket"],
      excluded_resource_urns: ["urn:cerebro:tenant:aws_s3_bucket:Example"],
      excluded_resources: [
        { type: "aws.s3_bucket", id: "bucket-a", reason: "duplicate test" },
        { urn: "urn:cerebro:tenant:gcp_project:project-a", type: undefined, id: undefined, reason: undefined },
      ],
    });
    expect(scopePolicyExclusionCount(policy)).toBe(7);
  });

  it("omits empty scope policies", () => {
    expect(normalizeScopePolicy({
      excluded_families: [" "],
      excluded_resource_urns: [],
      excluded_resources: [{ type: "aws.s3_bucket" }],
    })).toBeUndefined();
  });

  it("derives class families from advertised options", () => {
    expect(connectorScopeOptionFamilies({
      id: "aws.s3_bucket",
      label: "S3 buckets",
      families: [" s3_bucket ", "AWS.S3_BUCKET"],
    })).toEqual(["aws.s3_bucket", "s3_bucket"]);
    expect(connectorScopeOptionFamilies({ id: "gcp.project", label: "Projects" })).toEqual(["gcp.project"]);
  });
});

describe("dynamic connector definitions", () => {
  it("creates a reference-only JSON API draft by default", () => {
    const draft = defaultConnectorDefinitionDraft("tenant-a");

    expect(draft).toMatchObject({
      tenant_id: "tenant-a",
      runtime: "json_api",
      stage: "draft",
      auth: {
        model: "bearer_token",
        requires_references: true,
      },
    });
    expect(draft.config_fields?.[0]).toMatchObject({ key: "base_url", required: true });
    expect(draft.transport).toMatchObject({ base_url: "${config.base_url}", verification: { path: "/health" } });
    expect(draft.auth.credential_fields?.[0]).toMatchObject({ key: "token", secret: true, reference_only: true });
    expect(draft.resource_families?.[0]).toMatchObject({ id: "assets", method: "GET", id_field: "id" });
  });

  it("derives lifecycle and validation status from backend gates", () => {
    const definition: ConnectorDefinition = {
      tenant_id: "tenant-a",
      source_id: "example",
      display_name: "Example",
      runtime: "json_api",
      stage: "draft",
      auth: { model: "bearer_token" },
      validation: {
        status: "blocked",
        checks: [
          { id: "auth", label: "Auth", status: "ready", severity: "info" },
          { id: "resources", label: "Resources", status: "blocked", severity: "error", blocking: true },
        ],
      },
      promotion: { eligible_stages: ["sandbox"] },
    };

    expect(connectorDefinitionStatus(definition)).toBe("blocked");
    expect(connectorDefinitionBlockingChecks(definition)).toBe(1);
    expect(connectorDefinitionNextStage(definition)).toBe("sandbox");
  });

  it("derives source activation plan labels, links, and category counts", () => {
    expect(sourceActivationPlanStatusLabel("blocked")).toBe("Blocked");
    expect(sourceActivationPlanPath("tenant-a-example", "tenant-a")).toBe("/connectors/activation?definition_id=tenant-a-example&tenant_id=tenant-a");
    expect(sourceActivationPlanCategoryCounts({
      checklist: [
        { id: "definition.id", title: "Definition ID", category: "definition", status: "ready" },
        { id: "activation.scaffold", title: "Scaffold", category: "activation", status: "ready" },
        { id: "activation.fixture", title: "Fixture", category: "activation", status: "ready" },
      ],
    })).toEqual({ definition: 1, activation: 2 });
  });
});
