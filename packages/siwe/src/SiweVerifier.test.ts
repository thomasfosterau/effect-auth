import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import * as Auth from "effect-auth";
import {
  hashPersonalMessage,
  makeSiweVerifier,
  recoverPersonalSignatureAddress,
  SiweVerifierLayer,
} from "./SiweVerifier.js";

// --- A deterministic test wallet ---------------------------------------------

const privateKey = secp256k1.utils.randomPrivateKey();
const publicKey = secp256k1.getPublicKey(privateKey, false);
const address = `0x${Buffer.from(keccak_256(publicKey.slice(1)).slice(-20)).toString("hex")}`;

/** EIP-191 `personal_sign` with the test wallet: 65-byte `r || s || v` hex. */
const personalSign = (message: string): string => {
  const signature = secp256k1.sign(hashPersonalMessage(message), privateKey);
  const v = 27 + signature.recovery;
  return `0x${Buffer.from(signature.toCompactRawBytes()).toString("hex")}${v.toString(16).padStart(2, "0")}`;
};

describe("recoverPersonalSignatureAddress", () => {
  it("recovers the signer's address", () => {
    const message = "hello, effect-auth";
    expect(recoverPersonalSignatureAddress({ message, signature: personalSign(message) })).toBe(
      address,
    );
  });

  it("recovers a different address for a tampered message", () => {
    const signature = personalSign("original message");
    const recovered = recoverPersonalSignatureAddress({ message: "tampered message", signature });
    expect(recovered).not.toBe(address);
  });

  it("rejects malformed signatures", () => {
    expect(() => recoverPersonalSignatureAddress({ message: "x", signature: "0x1234" })).toThrow();
  });
});

describe("makeSiweVerifier", () => {
  const verifier = makeSiweVerifier();

  it("accepts a valid signature for the claimed address (case-insensitive)", async () => {
    const message = "sign in please";
    const ok = await Effect.runPromise(
      verifier.verifyMessage({
        message,
        signature: personalSign(message),
        address: address.toUpperCase().replace("0X", "0x"),
      }),
    );
    expect(ok).toBe(true);
  });

  it("rejects a signature from a different key", async () => {
    const message = "sign in please";
    const ok = await Effect.runPromise(
      verifier.verifyMessage({
        message,
        signature: personalSign(message),
        address: "0x0000000000000000000000000000000000000001",
      }),
    );
    expect(ok).toBe(false);
  });

  it("fails with SiweError on garbage input", async () => {
    const err = await Effect.runPromise(
      Effect.flip(verifier.verifyMessage({ message: "x", signature: "not-hex", address })),
    );
    expect(err).toBeInstanceOf(Auth.SiweError);
  });
});

// --- End to end through effect-auth's SiweService -----------------------------

const makeStores = () => {
  const nonces = new Map<string, Auth.SiweNonce>();
  const usersByWallet = new Map<string, Auth.User>();
  let userSeq = 0;

  const nonceStore: Auth.SiweNonceStore = {
    create: (n) => Effect.sync(() => (nonces.set(n.nonce, n), n)),
    get: (nonce) => Effect.succeed(nonces.get(nonce) ?? null),
    delete: (nonce) => Effect.sync(() => void nonces.delete(nonce)),
  };
  const userStore: Auth.SiweUserStore = {
    getUserByWalletAddress: (walletAddress) =>
      Effect.succeed(usersByWallet.get(walletAddress) ?? null),
    createUser: ({ walletAddress }) =>
      Effect.sync(() => {
        const now = new Date();
        const user: Auth.User = {
          id: `u${++userSeq}`,
          email: `${walletAddress}@wallet.invalid`,
          emailVerified: false,
          createdAt: now,
          updatedAt: now,
          attributes: { walletAddress },
        };
        usersByWallet.set(walletAddress, user);
        return user;
      }),
  };
  const sessionManager: Auth.SessionManager = {
    createSession: (userId) =>
      Effect.succeed({
        id: `s-${userId}`,
        userId,
        expiresAt: new Date(Date.now() + 3600_000),
        createdAt: new Date(),
        lastActivityAt: new Date(),
        attributes: {},
      }),
    validateSession: () => Effect.die("unused"),
    invalidateSession: () => Effect.die("unused"),
    invalidateUserSessions: () => Effect.void,
    listSessions: () => Effect.succeed([]),
    revokeOtherSessions: () => Effect.void,
    setSessionAttributes: () => Effect.die("unused"),
  };

  const layer = Layer.mergeAll(
    Layer.succeed(Auth.SiweNonceStoreTag)(nonceStore),
    Layer.succeed(Auth.SiweUserStoreTag)(userStore),
    Layer.succeed(Auth.SessionManagerTag)(sessionManager),
    SiweVerifierLayer,
    Auth.Hooks.Default,
  );
  return { layer, usersByWallet };
};

describe("SiweService end to end (real secp256k1 verifier)", () => {
  it("signs in with a wallet: nonce -> message -> signature -> session", async () => {
    const { layer, usersByWallet } = makeStores();
    const service = await Effect.runPromise(Auth.makeSiweService({ domain: "app.test" }));

    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const { nonce } = yield* service.generateNonce();
        const message = Auth.formatSiweMessage({
          domain: "app.test",
          address,
          statement: "Sign in to App",
          uri: "https://app.test",
          version: "1",
          chainId: 1,
          nonce,
          issuedAt: new Date().toISOString(),
        });
        const first = yield* service.verify({ message, signature: personalSign(message) });

        // A second sign-in (fresh nonce) reuses the same user.
        const again = yield* service.generateNonce();
        const message2 = Auth.formatSiweMessage({
          domain: "app.test",
          address,
          uri: "https://app.test",
          version: "1",
          chainId: 1,
          nonce: again.nonce,
          issuedAt: new Date().toISOString(),
        });
        const second = yield* service.verify({
          message: message2,
          signature: personalSign(message2),
        });

        // Nonces are single use: replaying the first message fails.
        const replay = yield* Effect.flip(
          service.verify({ message, signature: personalSign(message) }),
        );
        return { first, second, replay };
      }).pipe(Effect.provide(layer)),
    );

    expect(result.first.isNewUser).toBe(true);
    expect(result.first.walletAddress).toBe(address);
    expect(result.first.user.attributes["walletAddress"]).toBe(address);
    expect(result.first.session.userId).toBe(result.first.user.id);
    expect(result.second.isNewUser).toBe(false);
    expect(result.second.user.id).toBe(result.first.user.id);
    expect(result.replay).toBeInstanceOf(Auth.SiweError);
    expect(usersByWallet.size).toBe(1);
  });

  it("rejects a signature from the wrong wallet and a wrong domain", async () => {
    const { layer } = makeStores();
    const service = await Effect.runPromise(Auth.makeSiweService({ domain: "app.test" }));

    const otherKey = secp256k1.utils.randomPrivateKey();
    const signWithOther = (message: string): string => {
      const signature = secp256k1.sign(hashPersonalMessage(message), otherKey);
      const v = 27 + signature.recovery;
      return `0x${Buffer.from(signature.toCompactRawBytes()).toString("hex")}${v.toString(16).padStart(2, "0")}`;
    };

    const { wrongSigner, wrongDomain } = await Effect.runPromise(
      Effect.gen(function* () {
        const a = yield* service.generateNonce();
        const message = Auth.formatSiweMessage({
          domain: "app.test",
          address,
          uri: "https://app.test",
          version: "1",
          chainId: 1,
          nonce: a.nonce,
          issuedAt: new Date().toISOString(),
        });
        const wrongSigner = yield* Effect.flip(
          service.verify({ message, signature: signWithOther(message) }),
        );

        const b = yield* service.generateNonce();
        const foreign = Auth.formatSiweMessage({
          domain: "evil.test",
          address,
          uri: "https://evil.test",
          version: "1",
          chainId: 1,
          nonce: b.nonce,
          issuedAt: new Date().toISOString(),
        });
        const wrongDomain = yield* Effect.flip(
          service.verify({ message: foreign, signature: personalSign(foreign) }),
        );
        return { wrongSigner, wrongDomain };
      }).pipe(Effect.provide(layer)),
    );

    expect(wrongSigner).toBeInstanceOf(Auth.SiweError);
    expect(wrongDomain).toBeInstanceOf(Auth.SiweError);
  });
});
