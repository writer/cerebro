import { describe, expect, it } from "vitest";

import { tokenizeCypher } from "./CypherBlock";

describe("tokenizeCypher", () => {
  it("preserves parameter and operator punctuation", () => {
    const query = "MATCH (n) WHERE n.tenant = $tenantId AND n.name =~ 'a.*' RETURN n|?";

    expect(tokenizeCypher(query).map((token) => token.value).join("")).toBe(query);
  });
});
