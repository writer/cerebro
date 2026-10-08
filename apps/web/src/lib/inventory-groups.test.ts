import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { INVENTORY_GROUP_RULES, INVENTORY_GROUPS, inventoryGroupFor, inventoryGroupForEntityType, isInventoryGroupID } from "./inventory-groups";

const goSource = readFileSync(join(process.cwd(), "../../internal/graphquery/inventory_groups.go"), "utf8");

const goStringList = (body: string, key: string) => {
  const match = new RegExp(`\\b${key}:\\s*\\[\\]string\\{([^}]*)\\}`).exec(body);
  if (!match) return [];
  return [...match[1].matchAll(/"([^"]*)"/g)].map((entry) => entry[1]);
};

const goGroupRules = () => {
  const constants = Object.fromEntries(
    [...goSource.matchAll(/(InventoryGroup\w+)\s*=\s*"([a-z]+)"/g)].map((entry) => [entry[1], entry[2]]),
  );
  const body = goSource.slice(
    goSource.indexOf("func inventoryGroupRules()"),
    goSource.indexOf("func (rule inventoryGroupRule) matches"),
  );
  return [...body.matchAll(/\{\s*id:\s*(InventoryGroup\w+),([\s\S]*?)\n\t\t\},/g)].map((entry) => ({
    id: constants[entry[1]],
    exact: goStringList(entry[2], "exact"),
    prefixes: goStringList(entry[2], "prefixes"),
    suffixes: goStringList(entry[2], "suffixes"),
  }));
};

describe("inventory groups", () => {
  // The console sends a group id as category_id, so a group the service does
  // not know would silently return an unfiltered list.
  it("mirrors the group ids the service defines", () => {
    const serviceIDs = [...goSource.matchAll(/InventoryGroup\w+\s*=\s*"([a-z]+)"/g)].map((match) => match[1]);

    expect(serviceIDs.length).toBeGreaterThan(0);
    expect(INVENTORY_GROUPS.map((group) => group.id).sort()).toEqual([...serviceIDs].sort());
  });

  it("mirrors the group labels the service returns", () => {
    const serviceLabels = [...goSource.matchAll(/\blabel:\s*"([^"]+)"/g)].map((match) => match[1]);

    expect(serviceLabels.length).toBeGreaterThan(0);
    expect(INVENTORY_GROUPS.map((group) => group.label).sort()).toEqual([...serviceLabels].sort());
  });

  it("routes each group under inventory without hyphenated segments", () => {
    for (const group of INVENTORY_GROUPS) {
      expect(group.href).toBe(`/inventory/${group.id}`);
      expect(group.id).not.toContain("-");
      expect(group.summary).not.toBe("");
      expect(group.description).not.toBe("");
    }
  });

  // Fixture mode groups entity types in the browser, so the mirrored rules
  // must stay identical to the service rules, including their order.
  it("mirrors the service group rules exactly", () => {
    const serviceRules = goGroupRules();

    expect(serviceRules).toHaveLength(INVENTORY_GROUP_RULES.length);
    expect(serviceRules).toEqual(
      INVENTORY_GROUP_RULES.map((rule) => ({
        id: rule.id,
        exact: rule.exact,
        prefixes: rule.prefixes,
        suffixes: rule.suffixes,
      })),
    );
  });

  it("classifies entity types the way the service does", () => {
    expect(inventoryGroupForEntityType("okta.user")).toBe("identities");
    expect(inventoryGroupForEntityType("github.user")).toBe("identities");
    expect(inventoryGroupForEntityType("github.code.repository")).toBe("code");
    expect(inventoryGroupForEntityType("aws.ec2.instance")).toBe("cloud");
    expect(inventoryGroupForEntityType("runtime.secret")).toBe("secrets");
    // Several projectors join the parts with an underscore for the same concept.
    expect(inventoryGroupForEntityType("identity_user")).toBe("identities");
    expect(inventoryGroupForEntityType("storage_bucket")).toBe("cloud");
    expect(inventoryGroupForEntityType("endpoint_device")).toBe("devices");
    expect(inventoryGroupForEntityType("policy")).toBeUndefined();
    expect(inventoryGroupForEntityType("")).toBeUndefined();
  });

  it("resolves known ids and rejects unknown ones", () => {
    expect(inventoryGroupFor("identities")?.label).toBe("Identities");
    expect(inventoryGroupFor("compute-instances")).toBeUndefined();
    expect(inventoryGroupFor(undefined)).toBeUndefined();
    expect(isInventoryGroupID("secrets")).toBe(true);
    expect(isInventoryGroupID("not-a-group")).toBe(false);
  });
});
