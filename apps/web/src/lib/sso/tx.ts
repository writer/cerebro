import { hkdfSync } from "crypto";
import { EncryptJWT, jwtDecrypt } from "jose";

export const TX_TTL_SECONDS = 10 * 60;
const TX_KEY_INFO = "cerebro-web-sso-tx-v1";
const TX_AUDIENCE = "cerebro-web-sso-tx";

export type LoginTransaction = {
  connectionId: string;
  state: string;
  nonce?: string;
  codeVerifier?: string;
  samlRequestId?: string;
  returnTo: string;
  test: boolean;
  /** Actor that started an admin test login; recorded with the test result. */
  testActor?: string;
  createdAt: string;
};

export class TransactionError extends Error {
  expired: boolean;

  constructor(message: string, expired = false) {
    super(message);
    this.expired = expired;
  }
}

export const deriveTxKey = (secret: Uint8Array) =>
  new Uint8Array(hkdfSync("sha256", secret, new Uint8Array(0), TX_KEY_INFO, 32));

export const sealTransaction = async (tx: LoginTransaction, secret: Uint8Array, nowSeconds = Math.floor(Date.now() / 1000)) =>
  new EncryptJWT({ tx })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setAudience(TX_AUDIENCE)
    .setIssuedAt(nowSeconds)
    .setExpirationTime(nowSeconds + TX_TTL_SECONDS)
    .encrypt(deriveTxKey(secret));

const stringOrUndefined = (value: unknown) => (typeof value === "string" && value ? value : undefined);

export const openTransaction = async (
  token: string,
  secret: Uint8Array,
  now: Date = new Date(),
): Promise<LoginTransaction> => {
  let payload: Record<string, unknown>;
  try {
    ({ payload } = await jwtDecrypt(token, deriveTxKey(secret), {
      audience: TX_AUDIENCE,
      currentDate: now,
      keyManagementAlgorithms: ["dir"],
      contentEncryptionAlgorithms: ["A256GCM"],
      requiredClaims: ["exp", "iat"],
    }));
  } catch (error) {
    const code = (error as { code?: string } | null)?.code;
    if (code === "ERR_JWT_EXPIRED") throw new TransactionError("Login transaction expired.", true);
    throw new TransactionError("Login transaction is invalid.");
  }
  const tx = payload.tx as Record<string, unknown> | undefined;
  if (!tx || typeof tx !== "object") throw new TransactionError("Login transaction is invalid.");
  const connectionId = stringOrUndefined(tx.connectionId);
  const state = stringOrUndefined(tx.state);
  const returnTo = stringOrUndefined(tx.returnTo);
  const createdAt = stringOrUndefined(tx.createdAt);
  if (!connectionId || !state || !returnTo || !createdAt) throw new TransactionError("Login transaction is invalid.");
  return {
    connectionId,
    state,
    nonce: stringOrUndefined(tx.nonce),
    codeVerifier: stringOrUndefined(tx.codeVerifier),
    samlRequestId: stringOrUndefined(tx.samlRequestId),
    returnTo,
    test: tx.test === true,
    testActor: stringOrUndefined(tx.testActor),
    createdAt,
  };
};
