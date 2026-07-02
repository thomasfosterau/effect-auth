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
import * as Errors from "./Errors.js";
import {
  type EmailOtpPurpose,
  type EmailOtpRecord,
  type EmailOtpStore,
  EmailOtpStoreTag,
} from "./EmailOtp.js";
import {
  type EmailVerification,
  type EmailVerificationStore,
  EmailVerificationStoreTag,
} from "./EmailVerification.js";
import { type MagicLinkStore, MagicLinkStoreTag, type MagicLinkToken } from "./MagicLink.js";
import { type OAuthState, type OAuthStateStore, OAuthStateStoreTag } from "./OAuth.js";
import {
  type PasswordResetStore,
  PasswordResetStoreTag,
  type PasswordResetToken,
} from "./PasswordReset.js";
import { type RateLimitEntry, type RateLimitStore, RateLimitStoreTag } from "./RateLimit.js";
import {
  type PendingTwoFactor,
  type PendingTwoFactorStore,
  PendingTwoFactorStoreTag,
} from "./TwoFactor.js";
import { type ChallengeStore, ChallengeStoreTag, type WebAuthnChallenge } from "./WebAuthn.js";

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
 * Build an {@link OAuthStateStore} over the ambient `KeyValueStore`.
 */
export const makeOAuthStateStoreKV: Effect.Effect<
  OAuthStateStore,
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
        .pipe(
          Effect.flatMap((entry) =>
            entry
              ? Effect.succeed(entry)
              : Effect.fail(new Errors.AuthError({ message: `OAuth state not found: ${state}` })),
          ),
        ),
    delete: (state) => kv.remove(oauthStateKey(state), "oauthState.delete"),
  } satisfies OAuthStateStore;
});

/**
 * `OAuthStateStore` layer backed by `KeyValueStore`.
 */
export const OAuthStateStoreKV: Layer.Layer<
  OAuthStateStoreTag,
  never,
  KeyValueStore.KeyValueStore
> = Layer.effect(OAuthStateStoreTag, makeOAuthStateStoreKV);

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
 * Build a WebAuthn {@link ChallengeStore} over the ambient `KeyValueStore`.
 */
export const makeChallengeStoreKV: Effect.Effect<
  ChallengeStore,
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
        Effect.flatMap((stored) =>
          stored
            ? Effect.succeed(decodeChallenge(stored))
            : Effect.fail(new Errors.ChallengeNotFoundError({ message: "Challenge not found" })),
        ),
      ),
    delete: (challenge) => kv.remove(challengeKey(challenge), "challenge.delete"),
  } satisfies ChallengeStore;
});

/**
 * WebAuthn `ChallengeStore` layer backed by `KeyValueStore`.
 */
export const ChallengeStoreKV: Layer.Layer<ChallengeStoreTag, never, KeyValueStore.KeyValueStore> =
  Layer.effect(ChallengeStoreTag, makeChallengeStoreKV);

// ---------------------------------------------------------------------------
// RateLimitStore
// ---------------------------------------------------------------------------

const rateLimitKey = (key: string) => `rate-limit:${key}`;

/**
 * Build a {@link RateLimitStore} over the ambient `KeyValueStore`.
 *
 * `increment` is read-modify-write and therefore not atomic (see the module
 * docs) — fine for best-effort limiting, not for strict quota enforcement.
 * The `ttl` arguments are honoured logically via each entry's `resetAt`
 * rather than by backend-level expiry, since `KeyValueStore` has no TTL API.
 */
export const makeRateLimitStoreKV: Effect.Effect<
  RateLimitStore,
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
  } satisfies RateLimitStore;
});

/**
 * `RateLimitStore` layer backed by `KeyValueStore`.
 */
export const RateLimitStoreKV: Layer.Layer<RateLimitStoreTag, never, KeyValueStore.KeyValueStore> =
  Layer.effect(RateLimitStoreTag, makeRateLimitStoreKV);

// ---------------------------------------------------------------------------
// EmailVerificationStore
// ---------------------------------------------------------------------------

const emailVerificationTokenKey = (token: string) => `email-verification:token:${token}`;
const emailVerificationUserKey = (userId: string) => `email-verification:user:${userId}`;

/**
 * Build an {@link EmailVerificationStore} over the ambient `KeyValueStore`.
 *
 * `deleteByUserId` is served by a secondary index key per user holding the
 * user's live tokens (see the module docs for staleness guarantees).
 */
export const makeEmailVerificationStoreKV: Effect.Effect<
  EmailVerificationStore,
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
  } satisfies EmailVerificationStore;
});

/**
 * `EmailVerificationStore` layer backed by `KeyValueStore`.
 */
export const EmailVerificationStoreKV: Layer.Layer<
  EmailVerificationStoreTag,
  never,
  KeyValueStore.KeyValueStore
> = Layer.effect(EmailVerificationStoreTag, makeEmailVerificationStoreKV);

// ---------------------------------------------------------------------------
// PasswordResetStore
// ---------------------------------------------------------------------------

const passwordResetTokenKey = (token: string) => `password-reset:token:${token}`;
const passwordResetUserKey = (userId: string) => `password-reset:user:${userId}`;

/**
 * Build a {@link PasswordResetStore} over the ambient `KeyValueStore`.
 *
 * `deleteByUserId` is served by a secondary index key per user.
 */
export const makePasswordResetStoreKV: Effect.Effect<
  PasswordResetStore,
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
  } satisfies PasswordResetStore;
});

/**
 * `PasswordResetStore` layer backed by `KeyValueStore`.
 */
export const PasswordResetStoreKV: Layer.Layer<
  PasswordResetStoreTag,
  never,
  KeyValueStore.KeyValueStore
> = Layer.effect(PasswordResetStoreTag, makePasswordResetStoreKV);

// ---------------------------------------------------------------------------
// MagicLinkStore
// ---------------------------------------------------------------------------

const magicLinkTokenKey = (token: string) => `magic-link:token:${token}`;
const magicLinkEmailKey = (email: string) => `magic-link:email:${email}`;

/**
 * Build a {@link MagicLinkStore} over the ambient `KeyValueStore`.
 *
 * `deleteByEmail` is served by a secondary index key per email address.
 */
export const makeMagicLinkStoreKV: Effect.Effect<
  MagicLinkStore,
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
  } satisfies MagicLinkStore;
});

/**
 * `MagicLinkStore` layer backed by `KeyValueStore`.
 */
export const MagicLinkStoreKV: Layer.Layer<MagicLinkStoreTag, never, KeyValueStore.KeyValueStore> =
  Layer.effect(MagicLinkStoreTag, makeMagicLinkStoreKV);

// ---------------------------------------------------------------------------
// EmailOtpStore
// ---------------------------------------------------------------------------

const emailOtpKey = (email: string, purpose: EmailOtpPurpose) => `email-otp:${purpose}:${email}`;

/**
 * Build an {@link EmailOtpStore} over the ambient `KeyValueStore`.
 *
 * There is at most one active OTP per email + purpose pair, so the pair is
 * the key itself and no secondary index is needed. `incrementAttempts` is
 * read-modify-write (see the module docs on atomicity).
 */
export const makeEmailOtpStoreKV: Effect.Effect<EmailOtpStore, never, KeyValueStore.KeyValueStore> =
  Effect.gen(function* () {
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
    } satisfies EmailOtpStore;
  });

/**
 * `EmailOtpStore` layer backed by `KeyValueStore`.
 */
export const EmailOtpStoreKV: Layer.Layer<EmailOtpStoreTag, never, KeyValueStore.KeyValueStore> =
  Layer.effect(EmailOtpStoreTag, makeEmailOtpStoreKV);

// ---------------------------------------------------------------------------
// PendingTwoFactorStore
// ---------------------------------------------------------------------------

const pendingTwoFactorKey = (token: string) => `pending-two-factor:${token}`;

/**
 * Build a {@link PendingTwoFactorStore} over the ambient `KeyValueStore`.
 */
export const makePendingTwoFactorStoreKV: Effect.Effect<
  PendingTwoFactorStore,
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
  } satisfies PendingTwoFactorStore;
});

/**
 * `PendingTwoFactorStore` layer backed by `KeyValueStore`.
 */
export const PendingTwoFactorStoreKV: Layer.Layer<
  PendingTwoFactorStoreTag,
  never,
  KeyValueStore.KeyValueStore
> = Layer.effect(PendingTwoFactorStoreTag, makePendingTwoFactorStoreKV);

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
  | OAuthStateStoreTag
  | ChallengeStoreTag
  | RateLimitStoreTag
  | EmailVerificationStoreTag
  | PasswordResetStoreTag
  | MagicLinkStoreTag
  | EmailOtpStoreTag
  | PendingTwoFactorStoreTag,
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
