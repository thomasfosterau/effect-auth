/**
 * `KeyValueStore`-backed implementations of effect-auth's ephemeral stores.
 *
 * These stores hold short-lived token/state data (OAuth states, WebAuthn
 * challenges, rate-limit counters, verification / reset / magic-link tokens,
 * email OTPs and pending two-factor challenges) — a natural fit for a
 * key-value backend such as Redis, Cloudflare KV, or an in-memory map.
 *
 * Each layer requires the `KeyValueStore` service from
 * `effect/unstable/persistence`; provide any of its backends (e.g.
 * `KeyValueStore.layerMemory`, `KeyValueStore.layerFileSystem`,
 * `KeyValueStore.layerSql`) underneath.
 *
 * Records are serialized as JSON strings. All of these record shapes use
 * epoch-millisecond numbers for timestamps (no `Date` fields), so plain
 * `JSON.stringify`/`JSON.parse` roundtrips them; WebAuthn challenge bytes are
 * base64-encoded.
 *
 * ## Key layout
 *
 * Every store namespaces its keys, e.g. `oauth-state:${state}` or
 * `magic-link:token:${token}`.
 *
 * ## Secondary indexes
 *
 * A key-value store cannot scan by user id or email, so stores with
 * `deleteByUserId`/`deleteByEmail` maintain a secondary index key (e.g.
 * `email-verification:user:${userId}` holding a JSON array of live tokens).
 * The index is updated on create/delete. Tokens that simply expire (without
 * being read or deleted) leave garbage entries behind until the next
 * create/delete for the same user/email — this is safe because every
 * consuming service already checks `expiresAt` before honouring a record.
 *
 * ## Atomicity caveat
 *
 * `RateLimitStore.increment` (and `EmailOtpStore.incrementAttempts` / the
 * secondary index updates) are implemented as read-modify-write, which is not
 * atomic. Unlike a Redis `INCR`, two concurrent increments may both observe
 * the same count and only bump it once. This is acceptable for the KV
 * backend's intended use (best-effort rate limiting / attempt counting);
 * use a backend with atomic counters when strict enforcement is required.
 */
import { Effect, Layer } from "effect";
import { KeyValueStore } from "effect/unstable/persistence";
import * as Errors from "./Errors.ts";
import {
  type EmailOtpPurpose,
  type EmailOtpRecord,
  type EmailOtpStoreShape,
  EmailOtpStore,
} from "./EmailOtp.ts";
import {
  type Identifier,
  IdentifierStore,
  type IdentifierStoreShape,
  type IdentifierType,
} from "./Identifier.ts";
import {
  type EmailVerification,
  type EmailVerificationStoreShape,
  EmailVerificationStore,
} from "./EmailVerification.ts";
import { type MagicLinkStoreShape, MagicLinkStore, type MagicLinkToken } from "./MagicLink.ts";
import { type OAuthState, type OAuthStateStoreShape, OAuthStateStore } from "./OAuth/OAuth.ts";
import {
  type PasswordResetStoreShape,
  PasswordResetStore,
  type PasswordResetToken,
} from "./PasswordReset.ts";
import { type RateLimitEntry, type RateLimitStoreShape, RateLimitStore } from "./RateLimit.ts";
import {
  type PendingTwoFactor,
  type PendingTwoFactorStoreShape,
  PendingTwoFactorStore,
} from "./TwoFactor.ts";
import { type ChallengeStoreShape, ChallengeStore, type WebAuthnChallenge } from "./WebAuthn.ts";
import {
  type GoogleOneTapNonceEntry,
  type GoogleOneTapNonceStoreShape,
  GoogleOneTapNonceStore,
} from "./GoogleOneTap.ts";

// ---------------------------------------------------------------------------
// Codecs & helpers
// ---------------------------------------------------------------------------

const toAuthError =
  (label: string) =>
  (cause: unknown): Errors.AuthError =>
    new Errors.AuthError({
      message: `KeyValueStore ${label} failed${cause instanceof Error ? `: ${cause.message}` : ""}`,
    });

const toBase64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");
const fromBase64 = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "base64"));

/**
 * Small JSON codec over a raw {@link KeyValueStore.KeyValueStore}, mapping
 * storage failures to {@link Errors.AuthError}.
 */
const jsonKv = (kv: KeyValueStore.KeyValueStore) => {
  const read = <A>(key: string, label: string): Effect.Effect<A | null, Errors.AuthError> =>
    kv.get(key).pipe(
      Effect.mapError(toAuthError(label)),
      Effect.flatMap((value) =>
        value === undefined
          ? Effect.succeed(null)
          : Effect.try({
              try: () => JSON.parse(value) as A,
              catch: toAuthError(label),
            }),
      ),
    );

  const write = (
    key: string,
    value: unknown,
    label: string,
  ): Effect.Effect<void, Errors.AuthError> =>
    kv.set(key, JSON.stringify(value)).pipe(Effect.mapError(toAuthError(label)));

  const remove = (key: string, label: string): Effect.Effect<void, Errors.AuthError> =>
    kv.remove(key).pipe(Effect.mapError(toAuthError(label)));

  const readIndex = (
    key: string,
    label: string,
  ): Effect.Effect<readonly string[], Errors.AuthError> =>
    read<readonly string[]>(key, label).pipe(Effect.map((tokens) => tokens ?? []));

  /** Append an entry to a secondary index key (deduplicated). */
  const indexAdd = (
    key: string,
    entry: string,
    label: string,
  ): Effect.Effect<void, Errors.AuthError> =>
    readIndex(key, label).pipe(
      Effect.flatMap((entries) =>
        entries.includes(entry) ? Effect.void : write(key, [...entries, entry], label),
      ),
    );

  /** Remove an entry from a secondary index key, deleting the key when empty. */
  const indexRemove = (
    key: string,
    entry: string,
    label: string,
  ): Effect.Effect<void, Errors.AuthError> =>
    readIndex(key, label).pipe(
      Effect.flatMap((entries) => {
        const next = entries.filter((existing) => existing !== entry);
        return next.length === 0 ? remove(key, label) : write(key, next, label);
      }),
    );

  return { read, write, remove, readIndex, indexAdd, indexRemove };
};

// ---------------------------------------------------------------------------
// OAuthStateStore
// ---------------------------------------------------------------------------

const oauthStateKey = (state: string) => `oauth-state:${state}`;

/**
 * Build an {@link OAuthStateStoreShape} over the ambient `KeyValueStore`.
 */
export const makeOAuthStateStoreKV: Effect.Effect<
  OAuthStateStoreShape,
  never,
  KeyValueStore.KeyValueStore
> = Effect.gen(function* () {
  const kv = jsonKv(yield* KeyValueStore.KeyValueStore);
  return {
    create: (state) =>
      kv.write(oauthStateKey(state.state), state, "oauthState.create").pipe(Effect.as(state)),
    get: (state) =>
      kv
        .read<OAuthState>(oauthStateKey(state), "oauthState.get")
        .pipe(Effect.map((entry) => entry ?? null)),
    delete: (state) => kv.remove(oauthStateKey(state), "oauthState.delete"),
  } satisfies OAuthStateStoreShape;
});

/**
 * `OAuthStateStore` layer backed by `KeyValueStore`.
 */
export const OAuthStateStoreKV: Layer.Layer<OAuthStateStore, never, KeyValueStore.KeyValueStore> =
  Layer.effect(OAuthStateStore, makeOAuthStateStoreKV);

// ---------------------------------------------------------------------------
// WebAuthn ChallengeStore
// ---------------------------------------------------------------------------

/** JSON-safe encoding of a {@link WebAuthnChallenge} (bytes as base64). */
interface StoredChallenge {
  readonly challenge: string;
  readonly expiresAt: number;
  readonly userId?: string;
}

const challengeKey = (challenge: Uint8Array) => `webauthn-challenge:${toBase64(challenge)}`;

const decodeChallenge = (stored: StoredChallenge): WebAuthnChallenge => ({
  challenge: fromBase64(stored.challenge),
  expiresAt: stored.expiresAt,
  ...(stored.userId !== undefined ? { userId: stored.userId } : {}),
});

/**
 * Build a WebAuthn {@link ChallengeStoreShape} over the ambient `KeyValueStore`.
 */
export const makeChallengeStoreKV: Effect.Effect<
  ChallengeStoreShape,
  never,
  KeyValueStore.KeyValueStore
> = Effect.gen(function* () {
  const kv = jsonKv(yield* KeyValueStore.KeyValueStore);
  return {
    create: (challenge) =>
      kv
        .write(
          challengeKey(challenge.challenge),
          {
            challenge: toBase64(challenge.challenge),
            expiresAt: challenge.expiresAt,
            ...(challenge.userId !== undefined ? { userId: challenge.userId } : {}),
          } satisfies StoredChallenge,
          "challenge.create",
        )
        .pipe(Effect.as(challenge)),
    get: (challenge) =>
      kv.read<StoredChallenge>(challengeKey(challenge), "challenge.get").pipe(
        Effect.orDie,
        Effect.map((stored) => (stored ? decodeChallenge(stored) : null)),
      ),
    delete: (challenge) => kv.remove(challengeKey(challenge), "challenge.delete"),
  } satisfies ChallengeStoreShape;
});

/**
 * WebAuthn `ChallengeStore` layer backed by `KeyValueStore`.
 */
export const ChallengeStoreKV: Layer.Layer<ChallengeStore, never, KeyValueStore.KeyValueStore> =
  Layer.effect(ChallengeStore, makeChallengeStoreKV);

// ---------------------------------------------------------------------------
// RateLimitStore
// ---------------------------------------------------------------------------

const rateLimitKey = (key: string) => `rate-limit:${key}`;

/**
 * Build a {@link RateLimitStoreShape} over the ambient `KeyValueStore`.
 *
 * `increment` is read-modify-write and therefore not atomic (see the module
 * docs) — fine for best-effort limiting, not for strict quota enforcement.
 * The `ttl` arguments are honoured logically via each entry's `resetAt`
 * rather than by backend-level expiry, since `KeyValueStore` has no TTL API.
 */
export const makeRateLimitStoreKV: Effect.Effect<
  RateLimitStoreShape,
  never,
  KeyValueStore.KeyValueStore
> = Effect.gen(function* () {
  const kv = jsonKv(yield* KeyValueStore.KeyValueStore);
  const readEntry = (key: string) => kv.read<RateLimitEntry>(rateLimitKey(key), "rateLimit.get");
  return {
    get: (key) => readEntry(key).pipe(Effect.orDie),
    set: (key, entry, _ttl) => kv.write(rateLimitKey(key), entry, "rateLimit.set"),
    increment: (key, ttlSeconds) =>
      Effect.gen(function* () {
        const now = Date.now();
        const existing = yield* readEntry(key);
        if (existing == null || now >= existing.resetAt) {
          const entry: RateLimitEntry = { key, count: 1, resetAt: now + ttlSeconds * 1000 };
          yield* kv.write(rateLimitKey(key), entry, "rateLimit.increment");
          return 1;
        }
        const updated: RateLimitEntry = { ...existing, count: existing.count + 1 };
        yield* kv.write(rateLimitKey(key), updated, "rateLimit.increment");
        return updated.count;
      }),
    delete: (key) => kv.remove(rateLimitKey(key), "rateLimit.delete"),
  } satisfies RateLimitStoreShape;
});

/**
 * `RateLimitStore` layer backed by `KeyValueStore`.
 */
export const RateLimitStoreKV: Layer.Layer<RateLimitStore, never, KeyValueStore.KeyValueStore> =
  Layer.effect(RateLimitStore, makeRateLimitStoreKV);

// ---------------------------------------------------------------------------
// EmailVerificationStore
// ---------------------------------------------------------------------------

const emailVerificationTokenKey = (token: string) => `email-verification:token:${token}`;
const emailVerificationUserKey = (userId: string) => `email-verification:user:${userId}`;

/**
 * Build an {@link EmailVerificationStoreShape} over the ambient `KeyValueStore`.
 *
 * `deleteByUserId` is served by a secondary index key per user holding the
 * user's live tokens (see the module docs for staleness guarantees).
 */
export const makeEmailVerificationStoreKV: Effect.Effect<
  EmailVerificationStoreShape,
  never,
  KeyValueStore.KeyValueStore
> = Effect.gen(function* () {
  const kv = jsonKv(yield* KeyValueStore.KeyValueStore);
  return {
    create: (verification) =>
      Effect.gen(function* () {
        yield* kv.write(
          emailVerificationTokenKey(verification.token),
          verification,
          "emailVerification.create",
        );
        yield* kv.indexAdd(
          emailVerificationUserKey(verification.userId),
          verification.token,
          "emailVerification.create",
        );
        return verification;
      }),
    get: (token) =>
      kv.read<EmailVerification>(emailVerificationTokenKey(token), "emailVerification.get"),
    delete: (token) =>
      Effect.gen(function* () {
        const existing = yield* kv.read<EmailVerification>(
          emailVerificationTokenKey(token),
          "emailVerification.delete",
        );
        if (existing == null) return;
        yield* kv.remove(emailVerificationTokenKey(token), "emailVerification.delete");
        yield* kv.indexRemove(
          emailVerificationUserKey(existing.userId),
          token,
          "emailVerification.delete",
        );
      }),
    deleteByUserId: (userId) =>
      Effect.gen(function* () {
        const tokens = yield* kv.readIndex(
          emailVerificationUserKey(userId),
          "emailVerification.deleteByUserId",
        );
        yield* Effect.forEach(
          tokens,
          (token) =>
            kv.remove(emailVerificationTokenKey(token), "emailVerification.deleteByUserId"),
          { discard: true },
        );
        yield* kv.remove(emailVerificationUserKey(userId), "emailVerification.deleteByUserId");
      }),
  } satisfies EmailVerificationStoreShape;
});

/**
 * `EmailVerificationStore` layer backed by `KeyValueStore`.
 */
export const EmailVerificationStoreKV: Layer.Layer<
  EmailVerificationStore,
  never,
  KeyValueStore.KeyValueStore
> = Layer.effect(EmailVerificationStore, makeEmailVerificationStoreKV);

// ---------------------------------------------------------------------------
// PasswordResetStore
// ---------------------------------------------------------------------------

const passwordResetTokenKey = (token: string) => `password-reset:token:${token}`;
const passwordResetUserKey = (userId: string) => `password-reset:user:${userId}`;

/**
 * Build a {@link PasswordResetStoreShape} over the ambient `KeyValueStore`.
 *
 * `deleteByUserId` is served by a secondary index key per user.
 */
export const makePasswordResetStoreKV: Effect.Effect<
  PasswordResetStoreShape,
  never,
  KeyValueStore.KeyValueStore
> = Effect.gen(function* () {
  const kv = jsonKv(yield* KeyValueStore.KeyValueStore);
  return {
    create: (reset) =>
      Effect.gen(function* () {
        yield* kv.write(passwordResetTokenKey(reset.token), reset, "passwordReset.create");
        yield* kv.indexAdd(passwordResetUserKey(reset.userId), reset.token, "passwordReset.create");
        return reset;
      }),
    get: (token) => kv.read<PasswordResetToken>(passwordResetTokenKey(token), "passwordReset.get"),
    delete: (token) =>
      Effect.gen(function* () {
        const existing = yield* kv.read<PasswordResetToken>(
          passwordResetTokenKey(token),
          "passwordReset.delete",
        );
        if (existing == null) return;
        yield* kv.remove(passwordResetTokenKey(token), "passwordReset.delete");
        yield* kv.indexRemove(passwordResetUserKey(existing.userId), token, "passwordReset.delete");
      }),
    deleteByUserId: (userId) =>
      Effect.gen(function* () {
        const tokens = yield* kv.readIndex(
          passwordResetUserKey(userId),
          "passwordReset.deleteByUserId",
        );
        yield* Effect.forEach(
          tokens,
          (token) => kv.remove(passwordResetTokenKey(token), "passwordReset.deleteByUserId"),
          { discard: true },
        );
        yield* kv.remove(passwordResetUserKey(userId), "passwordReset.deleteByUserId");
      }),
  } satisfies PasswordResetStoreShape;
});

/**
 * `PasswordResetStore` layer backed by `KeyValueStore`.
 */
export const PasswordResetStoreKV: Layer.Layer<
  PasswordResetStore,
  never,
  KeyValueStore.KeyValueStore
> = Layer.effect(PasswordResetStore, makePasswordResetStoreKV);

// ---------------------------------------------------------------------------
// MagicLinkStore
// ---------------------------------------------------------------------------

const magicLinkTokenKey = (token: string) => `magic-link:token:${token}`;
const magicLinkEmailKey = (email: string) => `magic-link:email:${email}`;

/**
 * Build a {@link MagicLinkStoreShape} over the ambient `KeyValueStore`.
 *
 * `deleteByEmail` is served by a secondary index key per email address.
 */
export const makeMagicLinkStoreKV: Effect.Effect<
  MagicLinkStoreShape,
  never,
  KeyValueStore.KeyValueStore
> = Effect.gen(function* () {
  const kv = jsonKv(yield* KeyValueStore.KeyValueStore);
  return {
    create: (token) =>
      Effect.gen(function* () {
        yield* kv.write(magicLinkTokenKey(token.token), token, "magicLink.create");
        yield* kv.indexAdd(magicLinkEmailKey(token.email), token.token, "magicLink.create");
        return token;
      }),
    get: (token) => kv.read<MagicLinkToken>(magicLinkTokenKey(token), "magicLink.get"),
    getByEmail: (email) =>
      Effect.gen(function* () {
        const tokens = yield* kv.readIndex(magicLinkEmailKey(email), "magicLink.getByEmail");
        if (tokens.length === 0) return null;
        return yield* kv.read<MagicLinkToken>(
          magicLinkTokenKey(tokens[0]!),
          "magicLink.getByEmail",
        );
      }),
    delete: (token) =>
      Effect.gen(function* () {
        const existing = yield* kv.read<MagicLinkToken>(
          magicLinkTokenKey(token),
          "magicLink.delete",
        );
        if (existing == null) return;
        yield* kv.remove(magicLinkTokenKey(token), "magicLink.delete");
        yield* kv.indexRemove(magicLinkEmailKey(existing.email), token, "magicLink.delete");
      }),
    deleteByEmail: (email) =>
      Effect.gen(function* () {
        const tokens = yield* kv.readIndex(magicLinkEmailKey(email), "magicLink.deleteByEmail");
        yield* Effect.forEach(
          tokens,
          (token) => kv.remove(magicLinkTokenKey(token), "magicLink.deleteByEmail"),
          { discard: true },
        );
        yield* kv.remove(magicLinkEmailKey(email), "magicLink.deleteByEmail");
      }),
  } satisfies MagicLinkStoreShape;
});

/**
 * `MagicLinkStore` layer backed by `KeyValueStore`.
 */
export const MagicLinkStoreKV: Layer.Layer<MagicLinkStore, never, KeyValueStore.KeyValueStore> =
  Layer.effect(MagicLinkStore, makeMagicLinkStoreKV);

// ---------------------------------------------------------------------------
// EmailOtpStore
// ---------------------------------------------------------------------------

const emailOtpKey = (email: string, purpose: EmailOtpPurpose) => `email-otp:${purpose}:${email}`;

/**
 * Build an {@link EmailOtpStoreShape} over the ambient `KeyValueStore`.
 *
 * There is at most one active OTP per email + purpose pair, so the pair is
 * the key itself and no secondary index is needed. `incrementAttempts` is
 * read-modify-write (see the module docs on atomicity).
 */
export const makeEmailOtpStoreKV: Effect.Effect<
  EmailOtpStoreShape,
  never,
  KeyValueStore.KeyValueStore
> = Effect.gen(function* () {
  const kv = jsonKv(yield* KeyValueStore.KeyValueStore);
  return {
    upsert: (record) =>
      kv
        .write(emailOtpKey(record.email, record.purpose), record, "emailOtp.upsert")
        .pipe(Effect.as(record)),
    get: (email, purpose) => kv.read<EmailOtpRecord>(emailOtpKey(email, purpose), "emailOtp.get"),
    delete: (email, purpose) => kv.remove(emailOtpKey(email, purpose), "emailOtp.delete"),
    incrementAttempts: (email, purpose) =>
      Effect.gen(function* () {
        const record = yield* kv.read<EmailOtpRecord>(
          emailOtpKey(email, purpose),
          "emailOtp.incrementAttempts",
        );
        if (record == null) {
          return yield* new Errors.AuthError({ message: "OTP record not found" });
        }
        const updated: EmailOtpRecord = { ...record, attempts: record.attempts + 1 };
        yield* kv.write(emailOtpKey(email, purpose), updated, "emailOtp.incrementAttempts");
        return updated.attempts;
      }),
  } satisfies EmailOtpStoreShape;
});

/**
 * `EmailOtpStore` layer backed by `KeyValueStore`.
 */
export const EmailOtpStoreKV: Layer.Layer<EmailOtpStore, never, KeyValueStore.KeyValueStore> =
  Layer.effect(EmailOtpStore, makeEmailOtpStoreKV);

// ---------------------------------------------------------------------------
// PendingTwoFactorStore
// ---------------------------------------------------------------------------

const pendingTwoFactorKey = (token: string) => `pending-two-factor:${token}`;

/**
 * Build a {@link PendingTwoFactorStoreShape} over the ambient `KeyValueStore`.
 */
export const makePendingTwoFactorStoreKV: Effect.Effect<
  PendingTwoFactorStoreShape,
  never,
  KeyValueStore.KeyValueStore
> = Effect.gen(function* () {
  const kv = jsonKv(yield* KeyValueStore.KeyValueStore);
  return {
    create: (pending) =>
      kv
        .write(pendingTwoFactorKey(pending.token), pending, "pendingTwoFactor.create")
        .pipe(Effect.as(pending)),
    get: (token) => kv.read<PendingTwoFactor>(pendingTwoFactorKey(token), "pendingTwoFactor.get"),
    delete: (token) => kv.remove(pendingTwoFactorKey(token), "pendingTwoFactor.delete"),
  } satisfies PendingTwoFactorStoreShape;
});

/**
 * `PendingTwoFactorStore` layer backed by `KeyValueStore`.
 */
export const PendingTwoFactorStoreKV: Layer.Layer<
  PendingTwoFactorStore,
  never,
  KeyValueStore.KeyValueStore
> = Layer.effect(PendingTwoFactorStore, makePendingTwoFactorStoreKV);

// ---------------------------------------------------------------------------
// IdentifierStore
// ---------------------------------------------------------------------------

/** Wire format: dates stored as epoch-millisecond integers. */
interface StoredIdentifier {
  readonly id: string;
  readonly userId: string;
  readonly type: IdentifierType;
  readonly value: string;
  readonly verified: boolean;
  readonly verifiedAt?: number;
  readonly createdAt: number;
}

const identifierKey = (id: string) => `identifier:${id}`;
const identifierTypeValueKey = (type: IdentifierType, value: string) =>
  `identifier:type-value:${type}:${value}`;
const identifierUserKey = (userId: string) => `identifier:user:${userId}`;

const decodeIdentifier = (stored: StoredIdentifier): Identifier => ({
  id: stored.id,
  userId: stored.userId,
  type: stored.type,
  value: stored.value,
  verified: stored.verified,
  ...(stored.verifiedAt !== undefined ? { verifiedAt: new Date(stored.verifiedAt) } : {}),
  createdAt: new Date(stored.createdAt),
});

const encodeIdentifier = (identifier: Identifier): StoredIdentifier => ({
  id: identifier.id,
  userId: identifier.userId,
  type: identifier.type,
  value: identifier.value,
  verified: identifier.verified,
  ...(identifier.verifiedAt !== undefined ? { verifiedAt: identifier.verifiedAt.getTime() } : {}),
  createdAt: identifier.createdAt.getTime(),
});

/**
 * Build an {@link IdentifierStoreShape} over the ambient `KeyValueStore`.
 *
 * Key layout:
 * - `identifier:${id}` — primary record (full `StoredIdentifier`)
 * - `identifier:type-value:${type}:${value}` — id for `getByValue` lookups
 * - `identifier:user:${userId}` — JSON array of ids for `listByUser` /
 *   `deleteByUser`
 */
export const makeIdentifierStoreKV: Effect.Effect<
  IdentifierStoreShape,
  never,
  KeyValueStore.KeyValueStore
> = Effect.gen(function* () {
  const kv = jsonKv(yield* KeyValueStore.KeyValueStore);
  return {
    getByValue: (type, value) =>
      Effect.gen(function* () {
        const id = yield* kv.read<string>(
          identifierTypeValueKey(type, value),
          "identifier.getByValue",
        );
        if (id == null) return null;
        const stored = yield* kv.read<StoredIdentifier>(identifierKey(id), "identifier.getByValue");
        return stored == null ? null : decodeIdentifier(stored);
      }),

    listByUser: (userId) =>
      Effect.gen(function* () {
        const ids = yield* kv.readIndex(identifierUserKey(userId), "identifier.listByUser");
        const records = yield* Effect.forEach(
          ids,
          (id) => kv.read<StoredIdentifier>(identifierKey(id), "identifier.listByUser"),
          { concurrency: "unbounded" },
        );
        return records
          .filter((r): r is StoredIdentifier => r != null)
          .map(decodeIdentifier)
          .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
      }),

    create: (identifier) =>
      Effect.gen(function* () {
        const stored = encodeIdentifier(identifier);
        yield* kv.write(identifierKey(identifier.id), stored, "identifier.create");
        yield* kv.write(
          identifierTypeValueKey(identifier.type, identifier.value),
          identifier.id,
          "identifier.create",
        );
        yield* kv.indexAdd(
          identifierUserKey(identifier.userId),
          identifier.id,
          "identifier.create",
        );
        return identifier;
      }),

    setVerified: (id, verifiedAt) =>
      Effect.gen(function* () {
        const stored = yield* kv.read<StoredIdentifier>(
          identifierKey(id),
          "identifier.setVerified",
        );
        if (stored == null) return null;
        const updated: StoredIdentifier = {
          ...stored,
          verified: true,
          verifiedAt: verifiedAt.getTime(),
        };
        yield* kv.write(identifierKey(id), updated, "identifier.setVerified");
        return decodeIdentifier(updated);
      }),

    delete: (id) =>
      Effect.gen(function* () {
        const stored = yield* kv.read<StoredIdentifier>(identifierKey(id), "identifier.delete");
        if (stored == null) return;
        yield* kv.remove(identifierKey(id), "identifier.delete");
        yield* kv.remove(identifierTypeValueKey(stored.type, stored.value), "identifier.delete");
        yield* kv.indexRemove(identifierUserKey(stored.userId), id, "identifier.delete");
      }),

    deleteByUser: (userId) =>
      Effect.gen(function* () {
        const ids = yield* kv.readIndex(identifierUserKey(userId), "identifier.deleteByUser");
        yield* Effect.forEach(
          ids,
          (id) =>
            Effect.gen(function* () {
              const stored = yield* kv.read<StoredIdentifier>(
                identifierKey(id),
                "identifier.deleteByUser",
              );
              if (stored == null) return;
              yield* kv.remove(identifierKey(id), "identifier.deleteByUser");
              yield* kv.remove(
                identifierTypeValueKey(stored.type, stored.value),
                "identifier.deleteByUser",
              );
            }),
          { discard: true },
        );
        yield* kv.remove(identifierUserKey(userId), "identifier.deleteByUser");
      }),
  } satisfies IdentifierStoreShape;
});

/**
 * `IdentifierStore` layer backed by `KeyValueStore`.
 *
 * Unlike the ephemeral stores in {@link layerKV}, identifier records are
 * long-lived. Provide this layer alongside a `KeyValueStore` backend that
 * persists data across restarts (file system, Redis, …).
 */
export const IdentifierStoreKV: Layer.Layer<IdentifierStore, never, KeyValueStore.KeyValueStore> =
  Layer.effect(IdentifierStore, makeIdentifierStoreKV);

// ---------------------------------------------------------------------------
// GoogleOneTapNonceStore
// ---------------------------------------------------------------------------

const googleOneTapNonceKey = (nonce: string) => `google-one-tap-nonce:${nonce}`;

/**
 * Build a {@link GoogleOneTapNonceStoreShape} over the ambient `KeyValueStore`.
 *
 * Nonce entries are stored as JSON objects with an `expiresAt` epoch-ms field.
 * Expiry is enforced logically in `GoogleOneTap.signIn` (the entry is deleted
 * on first access regardless of validity, making every nonce single-use).
 */
export const makeGoogleOneTapNonceStoreKV: Effect.Effect<
  GoogleOneTapNonceStoreShape,
  never,
  KeyValueStore.KeyValueStore
> = Effect.gen(function* () {
  const kv = jsonKv(yield* KeyValueStore.KeyValueStore);
  return {
    create: (nonce, expiresAt) =>
      kv.write(
        googleOneTapNonceKey(nonce),
        { expiresAt } satisfies GoogleOneTapNonceEntry,
        "googleOneTapNonce.create",
      ),
    get: (nonce) =>
      kv.read<GoogleOneTapNonceEntry>(googleOneTapNonceKey(nonce), "googleOneTapNonce.get"),
    delete: (nonce) => kv.remove(googleOneTapNonceKey(nonce), "googleOneTapNonce.delete"),
  } satisfies GoogleOneTapNonceStoreShape;
});

/**
 * `GoogleOneTapNonceStore` layer backed by `KeyValueStore`.
 */
export const GoogleOneTapNonceStoreKV: Layer.Layer<
  GoogleOneTapNonceStore,
  never,
  KeyValueStore.KeyValueStore
> = Layer.effect(GoogleOneTapNonceStore, makeGoogleOneTapNonceStoreKV);

// ---------------------------------------------------------------------------
// Aggregate layer
// ---------------------------------------------------------------------------

/**
 * Every ephemeral store in one layer, backed by the ambient `KeyValueStore`.
 *
 * Combine with a persistent backend (e.g. `@effect-auth/sql`'s user/session
 * stores) for a complete auth stack.
 */
export const layerKV: Layer.Layer<
  | OAuthStateStore
  | ChallengeStore
  | RateLimitStore
  | EmailVerificationStore
  | PasswordResetStore
  | MagicLinkStore
  | EmailOtpStore
  | PendingTwoFactorStore,
  never,
  KeyValueStore.KeyValueStore
> = Layer.mergeAll(
  OAuthStateStoreKV,
  ChallengeStoreKV,
  RateLimitStoreKV,
  EmailVerificationStoreKV,
  PasswordResetStoreKV,
  MagicLinkStoreKV,
  EmailOtpStoreKV,
  PendingTwoFactorStoreKV,
);
