import { describe, expect, it } from "vitest";

import type { GRCGraph } from "@/lib/grc";

import {
  entityDetailHref,
  entityExploreHref,
  entityImpactHref,
  entityPivotQuestion,
  entityTypeKey,
  entityTypeLabel,
  parseEntityUrn,
  resolveEntityPeek,
} from "./entity-chip";

describe("parseEntityUrn", () => {
  it("splits tenant, entity type, and id", () => {
    expect(parseEntityUrn("urn:cerebro:writer:github_repo:writer/cerebro")).toEqual({
      tenant: "writer",
      entityType: "github_repo",
      id: "writer/cerebro",
    });
  });

  it("keeps colons inside the id segment", () => {
    expect(parseEntityUrn("urn:cerebro:writer:aws_role:arn:aws:iam::123:role/deploy")).toEqual({
      tenant: "writer",
      entityType: "aws_role",
      id: "arn:aws:iam::123:role/deploy",
    });
  });

  it("rejects non-cerebro values and incomplete urns", () => {
    expect(parseEntityUrn("not-a-urn")).toBeNull();
    expect(parseEntityUrn("urn:cerebro:writer")).toBeNull();
    expect(parseEntityUrn("urn:cerebro:writer:repo:")).toBeNull();
    expect(parseEntityUrn("")).toBeNull();
  });
});

describe("entityTypeKey", () => {
  it("maps entity types onto the graph palette families", () => {
    expect(entityTypeKey("finding")).toBe("finding");
    expect(entityTypeKey("okta_user")).toBe("identity");
    expect(entityTypeKey("aws_account")).toBe("identity");
    expect(entityTypeKey("endpoint")).toBe("asset");
    expect(entityTypeKey("github_repository")).toBe("asset");
    expect(entityTypeKey("npm_package")).toBe("package");
    expect(entityTypeKey("cve")).toBe("package");
    expect(entityTypeKey("malware_threat")).toBe("threat");
    expect(entityTypeKey("control")).toBe("default");
  });

  it("labels the default family as entity", () => {
    expect(entityTypeLabel("default")).toBe("entity");
    expect(entityTypeLabel("identity")).toBe("identity");
  });
});

describe("entity hrefs", () => {
  const urn = "urn:cerebro:writer:repo:writer/cerebro";
  const encoded = encodeURIComponent(urn);

  it("builds detail, impact, and explore links", () => {
    expect(entityDetailHref(urn)).toBe(`/inventory/${encoded}`);
    expect(entityImpactHref(urn)).toBe(`/impact?root_urn=${encoded}`);
    expect(entityExploreHref(urn)).toBe(`/explore?root_urn=${encoded}`);
  });

  it("builds a pivot question from the urn tail", () => {
    expect(entityPivotQuestion(urn)).toBe("Explore what connects to writer/cerebro");
  });
});

describe("resolveEntityPeek", () => {
  const graph: GRCGraph = {
    root: {
      urn: "urn:cerebro:writer:okta_user:jdoe",
      entity_type: "okta_user",
      label: "J. Doe",
      attributes: { risk_score: "88" },
    },
    neighbors: [
      {
        urn: "urn:cerebro:writer:aws_s3_bucket:customer-data",
        entity_type: "aws_s3_bucket",
        label: "customer-data",
        attributes: {},
      },
    ],
  };

  it("prefers graph node label, type, and risk when present", () => {
    const peek = resolveEntityPeek("urn:cerebro:writer:okta_user:jdoe", { graph });
    expect(peek).toMatchObject({
      label: "J. Doe",
      entityType: "okta_user",
      typeKey: "identity",
      risk: 88,
      riskLevel: "critical",
      source: "graph",
    });
  });

  it("reads neighbors as well as the root", () => {
    const peek = resolveEntityPeek("urn:cerebro:writer:aws_s3_bucket:customer-data", { graph });
    expect(peek).toMatchObject({
      label: "customer-data",
      typeKey: "default",
      risk: undefined,
      riskLevel: "unknown",
      source: "graph",
    });
  });

  it("falls back to urn parts when the entity is not in the graph", () => {
    const peek = resolveEntityPeek("urn:cerebro:writer:finding:f-1", { graph });
    expect(peek).toMatchObject({
      label: "f-1",
      entityType: "finding",
      typeKey: "finding",
      risk: undefined,
      source: "urn",
    });
  });

  it("keeps an explicit label override ahead of graph and urn labels", () => {
    const peek = resolveEntityPeek("urn:cerebro:writer:okta_user:jdoe", {
      graph,
      label: "the user",
    });
    expect(peek.label).toBe("the user");
  });

  it("ignores non-numeric risk scores", () => {
    const noisy: GRCGraph = {
      root: {
        urn: "urn:cerebro:writer:endpoint:host-01",
        entity_type: "endpoint",
        label: "host-01",
        attributes: { risk_score: "n/a" },
      },
    };
    const peek = resolveEntityPeek("urn:cerebro:writer:endpoint:host-01", { graph: noisy });
    expect(peek.risk).toBeUndefined();
    expect(peek.riskLevel).toBe("unknown");
  });
});
