import { Context, DateTime, Effect, MutableHashMap } from "effect";
import * as Option from "effect/Option";
import * as Arr from "effect/Array";
import { describe, expect, it } from "vite-plus/test";
import { type ApiKey, ApiKeyStore } from "./ApiKey.ts";
import { firstProofServices, proveAddress } from "./FirstProof.ts";
import { makeIdentifier, memoryIdentifierStore } from "./Identifier.ts";
import { MultiFactorStore, type MultiFactorRecord } from "./multifactor/MultiFactor.ts";
import { CredentialStore, type WebAuthnCredential } from "./multifactor/WebAuthn.ts";
import type { OAuthAccount } from "./oauth/OAuthAccount.ts";
import {
  memoryApiKeyStore,
  memoryEmailPasswordStore,
  memoryMultiFactorStore,
  memoryOAuthAccountStore,
  memoryTrustedDeviceStore,
  memoryUserTable,
} from "./testing/MemoryStores.ts";
import { type TrustedDeviceRecord, TrustedDeviceStore } from "./TrustedDevice.ts";

/** The account whose address is being proved, and an unrelated one whose credentials must stay. */
const SQUATTER = "user-squatter";
const BYSTANDER = "user-bystander";

const oauthAccount = (userId: string, provider: string): OAuthAccount => ({
  id: `${provider}-${userId}`,
  userId,
  provider,
  providerId: `${provider}-id-${userId}`,
  accessToken: "access",
  createdAt: 0,
  updatedAt: 0,
});

const passkey = (userId: string, id: string): WebAuthnCredential => ({
  id,
  userId,
  publicKey: new Uint8Array([1, 2, 3]),
  algorithm: -7,
  counter: 0,
  createdAt: 0,
});

const apiKey = (userId: string, id: string): ApiKey => ({
  id,
  start: "abcdef",
  keyHash: `hash-${id}`,
  userId,
  enabled: true,
  metadata: {},
  createdAt: 0,
  updatedAt: 0,
});

const enrolment = (userId: string): MultiFactorRecord => ({
  userId,
  secret: "JBSWY3DPEHPK3PXP",
  backupCodes: ["code-hash-1", "code-hash-2"],
  verified: true,
  createdAt: 0,
});

const trustedDevice = (userId: string, tokenHash: string): TrustedDeviceRecord => ({
  tokenHash,
  userId,
  createdAt: 0,
  expiresAt: Number.MAX_SAFE_INTEGER,
});

/** A `CredentialStore` over a map keyed by the credential id. */
const memoryPasskeyStore = (
  passkeys: MutableHashMap.MutableHashMap<string, WebAuthnCredential>,
): typeof CredentialStore.Service => ({
  create: (credential) =>
    Effect.sync(() => (MutableHashMap.set(passkeys, credential.id, credential), credential)),
  get: (id) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(passkeys, id))),
  getByCredentialId: (id) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(passkeys, id))),
  update: (credential) =>
    Effect.sync(() => (MutableHashMap.set(passkeys, credential.id, credential), credential)),
  delete: (id) => Effect.sync(() => void MutableHashMap.remove(passkeys, id)),
  listByUserId: (userId) =>
    Effect.sync(() =>
      Arr.fromIterable(MutableHashMap.values(passkeys)).filter((p) => p.userId === userId),
    ),
});

/**
 * The squatter's account holding `squatter@example.com` (verified or not) with
 * one credential of every kind, beside a bystander holding one of each too.
 */
const fixture = (verified: boolean) => {
  const table = memoryUserTable();
  MutableHashMap.set(table.passwordHashes, SQUATTER, "squatter-hash");
  const accounts = MutableHashMap.empty<string, OAuthAccount>();
  const passkeys = MutableHashMap.empty<string, WebAuthnCredential>();
  const keys = MutableHashMap.empty<string, ApiKey>();
  const enrolments = MutableHashMap.empty<string, MultiFactorRecord>();
  const devices = MutableHashMap.empty<string, TrustedDeviceRecord>();
  const credentials = {
    oauthAccounts: memoryOAuthAccountStore(table, accounts),
    passkeys: memoryPasskeyStore(passkeys),
    apiKeys: memoryApiKeyStore(keys),
    multiFactor: memoryMultiFactorStore(enrolments),
    trustedDevices: memoryTrustedDeviceStore(devices),
  };
  const revoked: Array<string> = [];
  const identifiers = memoryIdentifierStore();
  const identifier = makeIdentifier({
    userId: SQUATTER,
    type: "email",
    value: "squatter@example.com",
    verified,
    now: DateTime.toDateUtc(DateTime.makeUnsafe(0)),
  });
  Effect.runSync(
    Effect.gen(function* () {
      yield* identifiers.create(identifier);
      yield* Effect.forEach(
        [SQUATTER, BYSTANDER],
        (userId) =>
          Effect.all(
            [
              credentials.oauthAccounts.create(oauthAccount(userId, "github")),
              credentials.oauthAccounts.create(oauthAccount(userId, "gitlab")),
              credentials.passkeys.create(passkey(userId, `passkey-${userId}`)),
              credentials.apiKeys.create(apiKey(userId, `key-${userId}`)),
              credentials.multiFactor.upsert(enrolment(userId)),
              credentials.trustedDevices.upsert(trustedDevice(userId, `device-${userId}`)),
            ],
            { concurrency: 1, discard: true },
          ),
        { concurrency: 1, discard: true },
      );
    }),
  );
  const base = {
    identifiers,
    passwords: memoryEmailPasswordStore(table),
    sessions: {
      invalidateUserSessions: (userId: string) => Effect.sync(() => void revoked.push(userId)),
      revokeOtherSessions: (userId: string, keep: string) =>
        Effect.sync(() => void revoked.push(`${userId} except ${keep}`)),
    },
  };
  /** What each kind of credential holds per user after the proof. */
  const holdings = (userId: string) =>
    Effect.runSync(
      Effect.gen(function* () {
        return {
          oauthAccounts: (yield* credentials.oauthAccounts.getByUserId(userId))
            .map((account) => account.provider)
            .toSorted(),
          passkeys: (yield* credentials.passkeys.listByUserId(userId)).map((p) => p.id),
          apiKeys: (yield* credentials.apiKeys.listByUserId(userId)).map((key) => key.id),
          multiFactor: (yield* credentials.multiFactor.get(userId)) !== null,
          trustedDevice:
            (yield* credentials.trustedDevices.getByTokenHash(`device-${userId}`)) !== null,
        };
      }),
    );
  return {
    table,
    identifier,
    credentials,
    base,
    revoked,
    holdings,
    prove: (services: Parameters<typeof proveAddress>[0], proverSessionId?: string) =>
      Effect.runSync(proveAddress(services, identifier, proverSessionId)),
  };
};

const untouched = (userId: string) => ({
  oauthAccounts: ["github", "gitlab"],
  passkeys: [`passkey-${userId}`],
  apiKeys: [`key-${userId}`],
  multiFactor: true,
  trustedDevice: true,
});

describe("proveAddress: the first proof removes the earlier holder's credentials (#694)", () => {
  it("removes the account's linked OAuth accounts", () => {
    const f = fixture(false);
    f.prove({ ...f.base, oauthAccounts: f.credentials.oauthAccounts });
    expect(f.holdings(SQUATTER).oauthAccounts).toEqual([]);
    expect(f.holdings(BYSTANDER)).toEqual(untouched(BYSTANDER));
  });

  it("removes the account's passkeys", () => {
    const f = fixture(false);
    f.prove({ ...f.base, passkeys: f.credentials.passkeys });
    expect(f.holdings(SQUATTER).passkeys).toEqual([]);
    expect(f.holdings(BYSTANDER)).toEqual(untouched(BYSTANDER));
  });

  it("removes the account's API keys", () => {
    const f = fixture(false);
    f.prove({ ...f.base, apiKeys: f.credentials.apiKeys });
    expect(f.holdings(SQUATTER).apiKeys).toEqual([]);
    expect(f.holdings(BYSTANDER)).toEqual(untouched(BYSTANDER));
  });

  it("removes the account's multi-factor enrolment (TOTP secret and backup codes)", () => {
    const f = fixture(false);
    f.prove({ ...f.base, multiFactor: f.credentials.multiFactor });
    expect(f.holdings(SQUATTER).multiFactor).toBe(false);
    expect(f.holdings(BYSTANDER)).toEqual(untouched(BYSTANDER));
  });

  it("removes the account's trusted devices", () => {
    const f = fixture(false);
    f.prove({ ...f.base, trustedDevices: f.credentials.trustedDevices });
    expect(f.holdings(SQUATTER).trustedDevice).toBe(false);
    expect(f.holdings(BYSTANDER)).toEqual(untouched(BYSTANDER));
  });

  it("removes every kind at once, with the password and sessions, and verifies the address", () => {
    const f = fixture(false);
    const proved = f.prove({ ...f.base, ...f.credentials }, "prover-session");
    expect(f.holdings(SQUATTER)).toEqual({
      oauthAccounts: [],
      passkeys: [],
      apiKeys: [],
      multiFactor: false,
      trustedDevice: false,
    });
    expect(f.holdings(BYSTANDER)).toEqual(untouched(BYSTANDER));
    expect(MutableHashMap.has(f.table.passwordHashes, SQUATTER)).toBe(false);
    expect(f.revoked).toEqual([`${SQUATTER} except prover-session`]);
    expect(proved?.verified).toBe(true);
  });

  it("still clears the password and sessions when the app provides no credential store", () => {
    const f = fixture(false);
    f.prove(f.base);
    expect(MutableHashMap.has(f.table.passwordHashes, SQUATTER)).toBe(false);
    expect(f.revoked).toEqual([SQUATTER]);
    expect(f.holdings(SQUATTER)).toEqual(untouched(SQUATTER));
  });

  it("removes nothing from an account whose address is already verified", () => {
    const f = fixture(true);
    const proved = f.prove({ ...f.base, ...f.credentials });
    expect(f.holdings(SQUATTER)).toEqual(untouched(SQUATTER));
    expect(MutableHashMap.has(f.table.passwordHashes, SQUATTER)).toBe(true);
    expect(f.revoked).toEqual([]);
    expect(proved?.verified).toBe(true);
  });
});

describe("firstProofServices", () => {
  it("adds each credential store the context provides to the caller's services, and leaves the rest undefined", () => {
    const f = fixture(false);
    const resolved = Effect.runSync(
      firstProofServices(f.base).pipe(
        Effect.provide(
          Context.merge(
            Context.make(ApiKeyStore, f.credentials.apiKeys),
            Context.merge(
              Context.make(CredentialStore, f.credentials.passkeys),
              Context.merge(
                Context.make(MultiFactorStore, f.credentials.multiFactor),
                Context.make(TrustedDeviceStore, f.credentials.trustedDevices),
              ),
            ),
          ),
        ),
      ),
    );
    expect(resolved).toEqual({
      ...f.base,
      oauthAccounts: undefined,
      passkeys: f.credentials.passkeys,
      apiKeys: f.credentials.apiKeys,
      multiFactor: f.credentials.multiFactor,
      trustedDevices: f.credentials.trustedDevices,
    });
  });
});
