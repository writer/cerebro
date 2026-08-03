import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadEd25519TransportSigner } from "../src/runtime/slack-transport-v2-runtime.js";

test("transport signer reads one private regular-file handle", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-transport-signer-"));
  try {
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyPath = join(root, "transport-signing-key.pem");
    await writeFile(
      keyPath,
      privateKey.export({ format: "pem", type: "pkcs8" }),
      { mode: 0o600 },
    );

    const signer = await loadEd25519TransportSigner({
      candidatePrincipalRef: "principal:candidate",
      keyPath,
      keyRef: "key:transport",
      principalRef: "principal:transport",
    });
    assert.equal(signer.signer.principal_ref, "principal:transport");
    assert.match(await signer.signPayloadDigest(`sha256:${"a".repeat(64)}`), /^[A-Za-z0-9+/]+={0,2}$/u);

    await chmod(keyPath, 0o644);
    await assert.rejects(
      loadEd25519TransportSigner({
        candidatePrincipalRef: "principal:candidate",
        keyPath,
        keyRef: "key:transport",
        principalRef: "principal:transport",
      }),
      /private regular file/u,
    );

    const linkPath = join(root, "transport-signing-key-link.pem");
    await symlink(keyPath, linkPath);
    await assert.rejects(
      loadEd25519TransportSigner({
        candidatePrincipalRef: "principal:candidate",
        keyPath: linkPath,
        keyRef: "key:transport",
        principalRef: "principal:transport",
      }),
    );
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});
