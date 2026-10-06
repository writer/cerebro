import { describe, expect, it } from "vitest";

import type { GRCInventoryAsset, GRCInventoryCategory } from "@/lib/grc";
import { inventoryMetadataMatch, inventorySourceOptions, inventoryTypeOptions } from "./inventory-search";

const asset = (overrides: Partial<GRCInventoryAsset> = {}): GRCInventoryAsset => ({
  urn: "urn:cerebro:writer:aws.s3.bucket:reports",
  entity_type: "aws.s3.bucket",
  label: "reports",
  source_id: "aws",
  attributes: { account_id: "123456789012", region: "us-east-1" },
  ...overrides,
});

const category = (overrides: Partial<GRCInventoryCategory> = {}): GRCInventoryCategory => ({
  id: "storage",
  label: "Storage",
  entity_types: ["aws.s3.bucket"],
  count: 1,
  ...overrides,
});

describe("inventoryMetadataMatch", () => {
  it("explains a hit that only the metadata contains", () => {
    expect(inventoryMetadataMatch(asset(), "us-east-1")).toEqual({ key: "region", value: "us-east-1" });
    expect(inventoryMetadataMatch(asset(), "123456789012")).toEqual({ key: "account_id", value: "123456789012" });
  });

  it("stays quiet when the row already shows the match", () => {
    expect(inventoryMetadataMatch(asset(), "reports")).toBeNull();
    expect(inventoryMetadataMatch(asset(), "aws.s3.bucket")).toBeNull();
  });

  it("ignores case and surrounding space", () => {
    expect(inventoryMetadataMatch(asset(), "  US-EAST-1 ")).toEqual({ key: "region", value: "us-east-1" });
  });

  it("returns nothing without a query, without attributes, or without a hit", () => {
    expect(inventoryMetadataMatch(asset(), "")).toBeNull();
    expect(inventoryMetadataMatch(asset(), "   ")).toBeNull();
    expect(inventoryMetadataMatch(asset({ attributes: undefined }), "us-east-1")).toBeNull();
    expect(inventoryMetadataMatch(asset(), "eu-west-2")).toBeNull();
  });
});

describe("inventoryTypeOptions", () => {
  it("collects every type across categories, deduplicated and sorted", () => {
    const options = inventoryTypeOptions([
      category({ entity_types: ["aws.s3.bucket", "aws.ec2.instance"] }),
      category({ id: "identity", entity_types: ["okta.user", "aws.s3.bucket"] }),
    ]);
    expect(options).toEqual(["aws.ec2.instance", "aws.s3.bucket", "okta.user"]);
  });

  it("drops blank entries and tolerates a category with no types", () => {
    expect(inventoryTypeOptions([category({ entity_types: ["", "  "] })])).toEqual([]);
    expect(inventoryTypeOptions([{ id: "x", label: "X", count: 0 } as GRCInventoryCategory])).toEqual([]);
    expect(inventoryTypeOptions([])).toEqual([]);
  });
});

describe("inventorySourceOptions", () => {
  it("lists the distinct sources present in the loaded rows", () => {
    expect(inventorySourceOptions([asset(), asset({ source_id: "okta" }), asset({ source_id: "aws" })]))
      .toEqual(["aws", "okta"]);
  });

  it("skips rows with no source", () => {
    expect(inventorySourceOptions([asset({ source_id: undefined }), asset({ source_id: " " })])).toEqual([]);
  });
});
