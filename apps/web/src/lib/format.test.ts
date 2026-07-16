import { describe, expect, it } from "vitest";

import { countLabel, pluralize } from "./format";

describe("pluralize", () => {
  it("returns the singular form for exactly one", () => {
    expect(pluralize(1, "finding")).toBe("finding");
    expect(pluralize(-1, "finding")).toBe("finding");
  });

  it("returns the plural form for zero and many", () => {
    expect(pluralize(0, "finding")).toBe("findings");
    expect(pluralize(3, "finding")).toBe("findings");
  });

  it("uses an explicit plural when the default suffix is wrong", () => {
    expect(pluralize(1, "entity", "entities")).toBe("entity");
    expect(pluralize(2, "entity", "entities")).toBe("entities");
  });
});

describe("countLabel", () => {
  it("joins the count with the correct noun form", () => {
    expect(countLabel(1, "item")).toBe("1 item");
    expect(countLabel(0, "item")).toBe("0 items");
    expect(countLabel(2, "mapped objective")).toBe("2 mapped objectives");
  });
});
