import {
  createVerify,
  generateKeyPairSync,
} from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  parseArgs,
  portableEnvironment,
  run,
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
          DDESK_CARGO_EMERGENCY_FREE_BYTES: "17179869184",
          DDESK_CARGO_RESERVATION_BYTES: "8589934592",
          CEREBRO_API_KEY: "legacy-go-key",
          CEREBRO_HTTP_ADDR: "127.0.0.1:8000",
          UNRELATED_SECRET: "must-not-cross-process-boundary",
        },
        { CEREBRO_RUST_BIND: "127.0.0.1:8001" },
      ),
    ).toEqual({
      CEREBRO_RUST_BIND: "127.0.0.1:8001",
      DDESK_CARGO_EMERGENCY_FREE_BYTES: "17179869184",
      DDESK_CARGO_RESERVATION_BYTES: "8589934592",
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
      scope: "cerebro:read cerebro:actions:read identity:read",
      sub: "rust-e2e-user",
      tenant_id: "tenant-demo",
    });
    expect(valid).toBe(true);
  });

  it("keeps command stderr out of machine-readable stdout", async () => {
    const output = await run(
      process.execPath,
      [
        "-e",
        "process.stderr.write('runtime warning'); process.stdout.write('{\"ready\":true}')",
      ],
      {
        capture: "stdout",
        cwd: process.cwd(),
        env: portableEnvironment(),
      },
      Date.now() + 5_000,
    );

    expect(JSON.parse(output)).toEqual({ ready: true });
  });
});
