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
import { type OidcToken, OidcTokenStore } from "./OidcProvider.ts";
import {
  memoryApiKeyStore,
  memoryEmailPasswordStore,
  memoryMultiFactorStore,
  memoryOAuthAccountStore,
  memoryOidcTokenStore,
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

const oidcToken = (userId: string, kind: OidcToken["kind"]): OidcToken => ({
  tokenHash: `${kind}-${userId}`,
  kind,
  clientId: "client",
  userId,
  scopes: ["openid"],
  expiresAt: Number.MAX_SAFE_INTEGER,
  createdAt: 0,
  familyId: `family-${userId}`,
});

/** The phone numbers seeded per user: a `verified` one was proven by its holder. */
const PHONES = [
  { userId: SQUATTER, value: "+15550000001", verified: false },
  { userId: SQUATTER, value: "+15550000002", verified: true },
  { userId: BYSTANDER, value: "+15550000003", verified: false },
] as const;

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
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      Arr.forEach(
        Arr.filter(Arr.fromIterable(MutableHashMap.values(passkeys)), (p) => p.userId === userId),
        (p) => void MutableHashMap.remove(passkeys, p.id),
      );
    }),
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
  const tokens = MutableHashMap.empty<string, OidcToken>();
  const credentials = {
    oauthAccounts: memoryOAuthAccountStore(table, accounts),
    passkeys: memoryPasskeyStore(passkeys),
    apiKeys: memoryApiKeyStore(keys),
    multiFactor: memoryMultiFactorStore(enrolments),
    trustedDevices: memoryTrustedDeviceStore(devices),
    oidcTokens: memoryOidcTokenStore(tokens),
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
        PHONES,
        (phone) =>
          identifiers.create(
            makeIdentifier({
              ...phone,
              type: "phone",
              now: DateTime.toDateUtc(DateTime.makeUnsafe(0)),
            }),
          ),
        { concurrency: 1, discard: true },
      );
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
              credentials.oidcTokens.create(oidcToken(userId, "access")),
              credentials.oidcTokens.create(oidcToken(userId, "refresh")),
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
  /** The phone numbers `userId` holds after the proof. */
  const phones = (userId: string) =>
    Effect.runSync(identifiers.listByUser(userId))
      .filter((held) => held.type === "phone")
      .map((held) => held.value)
      .toSorted();
  /** The kinds of OIDC-provider token `userId` holds after the proof. */
  const oidcTokens = (userId: string) =>
    Arr.fromIterable(MutableHashMap.values(tokens))
      .filter((token) => token.userId === userId)
      .map((token) => token.kind)
      .toSorted();
  return {
    table,
    identifier,
    phones,
    oidcTokens,
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
    expect(f.phones(SQUATTER)).toEqual(["+15550000002"]);
    expect(f.oidcTokens(SQUATTER)).toEqual([]);
    expect(f.holdings(BYSTANDER)).toEqual(untouched(BYSTANDER));
    expect(f.oidcTokens(BYSTANDER)).toEqual(["access", "refresh"]);
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
    expect(f.phones(SQUATTER)).toEqual(["+15550000001", "+15550000002"]);
    expect(f.oidcTokens(SQUATTER)).toEqual(["access", "refresh"]);
    expect(MutableHashMap.has(f.table.passwordHashes, SQUATTER)).toBe(true);
    expect(f.revoked).toEqual([]);
    expect(proved?.verified).toBe(true);
  });
});

describe("proveAddress: the first proof removes the earlier holder's phone and OIDC access (#704)", () => {
  it("removes the account's unverified phone identifiers and keeps a verified one", () => {
    const f = fixture(false);
    f.prove(f.base);
    // The unverified number may be the squatter's; the verified one was proven by its holder.
    expect(f.phones(SQUATTER)).toEqual(["+15550000002"]);
    expect(f.phones(BYSTANDER)).toEqual(["+15550000003"]);
  });

  it("revokes the account's OIDC-provider access and refresh tokens", () => {
    const f = fixture(false);
    f.prove({ ...f.base, oidcTokens: f.credentials.oidcTokens });
    expect(f.oidcTokens(SQUATTER)).toEqual([]);
    expect(f.oidcTokens(BYSTANDER)).toEqual(["access", "refresh"]);
    expect(f.holdings(BYSTANDER)).toEqual(untouched(BYSTANDER));
  });

  it("leaves OIDC-provider tokens alone when the app provides no OidcTokenStore", () => {
    const f = fixture(false);
    f.prove(f.base);
    expect(f.oidcTokens(SQUATTER)).toEqual(["access", "refresh"]);
    expect(f.revoked).toEqual([SQUATTER]);
  });

  it("removes the phones and tokens before it revokes the sessions", () => {
    const f = fixture(false);
    const order: Array<string> = [];
    f.prove({
      ...f.base,
      identifiers: {
        ...f.base.identifiers,
        delete: (id) =>
          Effect.andThen(
            Effect.sync(() => void order.push("phone")),
            f.base.identifiers.delete(id),
          ),
      },
      oidcTokens: {
        deleteByUserId: (userId) =>
          Effect.andThen(
            Effect.sync(() => void order.push("oidc")),
            f.credentials.oidcTokens.deleteByUserId(userId),
          ),
      },
      sessions: {
        ...f.base.sessions,
        invalidateUserSessions: (userId) =>
          Effect.andThen(
            Effect.sync(() => void order.push("sessions")),
            f.base.sessions.invalidateUserSessions(userId),
          ),
      },
    });
    expect(order).toEqual(["phone", "oidc", "sessions"]);
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
                Context.merge(
                  Context.make(TrustedDeviceStore, f.credentials.trustedDevices),
                  Context.make(OidcTokenStore, f.credentials.oidcTokens),
                ),
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
      oidcTokens: f.credentials.oidcTokens,
    });
  });
});
