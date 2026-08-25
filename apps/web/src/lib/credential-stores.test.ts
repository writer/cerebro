import { describe, expect, it } from "vitest";

import {
  credentialStoreBindingsMatchingQuery,
  credentialStoreMatchesQuery,
  type CredentialStoreOperational,
} from "@/lib/credential-stores";

const environmentStore: CredentialStoreOperational = {
  store: {
    id: "environment_managed",
    label: "Environment managed",
    provider: "Deployment",
    available: true,
    mode: "environment_managed",
    status: "available",
    description: "Secrets are resolved inside the backend process.",
  },
  health: { status: "in_use" },
  usage: {
    connections: 2,
    credentials: 0,
    bindings: 2,
    field_references: 4,
    issues: 0,
  },
  bindings: [
    {
      id: "sentinelone-agent",
      credential_store_id: "environment_managed",
      source_id: "sentinelone",
      source_name: "SentinelOne",
      runtime_id: "writer-sentinelone-agent",
      fields: ["base_url", "token"],
    },
    {
      id: "okta-user",
      credential_store_id: "environment_managed",
      source_id: "okta",
      source_name: "Okta",
      runtime_id: "writer-okta-user",
      fields: ["domain", "token"],
    },
  ],
};

describe("credential store search", () => {
  it("keeps a store visible when one nested runtime matches", () => {
    expect(credentialStoreMatchesQuery(environmentStore, "SentinelOne")).toBe(true);
  });

  it("returns only runtime bindings that match a nested runtime query", () => {
    expect(credentialStoreBindingsMatchingQuery([environmentStore], "SentinelOne")).toEqual([
      expect.objectContaining({ id: "sentinelone-agent", credential_store_label: "Environment managed" }),
    ]);
  });

  it("returns every runtime binding when store metadata matches", () => {
    expect(credentialStoreBindingsMatchingQuery([environmentStore], "Environment managed")).toHaveLength(2);
  });

  it("matches runtime fields without retaining unrelated bindings", () => {
    expect(credentialStoreBindingsMatchingQuery([environmentStore], "domain")).toEqual([
      expect.objectContaining({ id: "okta-user" }),
    ]);
  });
});
