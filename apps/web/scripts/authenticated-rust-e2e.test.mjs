import {
  createVerify,
  generateKeyPairSync,
} from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  parseArgs,
  portableEnvironment,
  signedBearerToken,
} from "./authenticated-rust-e2e.mjs";

describe("authenticated Rust web integration helpers", () => {
  it("parses bounded command options", () => {
    expect(
      parseArgs(["--timeout-ms=120000", "--artifact-dir", "/tmp/evidence"]),
    ).toEqual({
      artifactRoot: "/tmp/evidence",
      timeoutMs: 120000,
    });
    expect(() => parseArgs(["--timeout-ms", "0"])).toThrow(
      "requires a positive integer",
    );
    expect(() => parseArgs(["--unknown"])).toThrow("Unknown option");
  });

  it("does not inherit unrelated process configuration", () => {
    expect(
      portableEnvironment(
        {
          HOME: "/tmp/home",
          PATH: "/bin",
          UNRELATED_SECRET: "must-not-cross-process-boundary",
        },
        { CEREBRO_HTTP_ADDR: "127.0.0.1:8000" },
      ),
    ).toEqual({
      CEREBRO_HTTP_ADDR: "127.0.0.1:8000",
      HOME: "/tmp/home",
      PATH: "/bin",
    });
  });

  it("creates an RS256 bearer token for the local issuer and audience", () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    const token = signedBearerToken(
      privateKey,
      "http://127.0.0.1:41111",
      Date.UTC(2026, 6, 28),
    );
    const [encodedHeader, encodedPayload, signature] = token.split(".");
    const header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString());
    const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString());
    const valid = createVerify("RSA-SHA256")
      .update(`${encodedHeader}.${encodedPayload}`)
      .end()
      .verify(publicKey, signature, "base64url");

    expect(header).toMatchObject({ alg: "RS256", kid: "local-e2e-key" });
    expect(payload).toMatchObject({
      aud: "cerebro-local-web",
      iss: "http://127.0.0.1:41111",
      sub: "rust-e2e-user",
    });
    expect(valid).toBe(true);
  });
});
