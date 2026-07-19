import { describe, expect, it } from "vitest";

import { parseSmokeDockerArgs } from "./smoke-docker.mjs";

describe("parseSmokeDockerArgs", () => {
  it("uses a portable local image and an ephemeral port by default", () => {
    expect(parseSmokeDockerArgs([])).toEqual({
      image: "cerebro-web:ci",
      port: 0,
    });
  });

  it("accepts an explicit image and port", () => {
    expect(parseSmokeDockerArgs(["cerebro-web:test", "--port=43100"])).toEqual({
      image: "cerebro-web:test",
      port: 43100,
    });
  });
});
