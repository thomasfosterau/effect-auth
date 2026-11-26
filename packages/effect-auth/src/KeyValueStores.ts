/**
 * `KeyValueStore` (`effect/persistence`) implementations of the ephemeral
 * stores. The token and state stores ({@link layerKV}) suit a deployment; the
 * counter stores and `IdentifierStoreKV` ({@link layerKVSingleProcess}) are
 * single-process only. Never keep single-use records on an eventually
 * consistent backend, and provide a {@link KeyValueStoreTake} behind several
 * instances.
 */
import {
  Clock,
  Context,
  DateTime,
  Duration,
  Effect,
  Layer,
  MutableHashMap,
  Order,
  Result,
  Semaphore,
  Struct,
} from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import { Base64 } from "effect/encoding";
import { KeyValueStore } from "effect/persistence";
import * as Errors from "./Errors.ts";
import { type EmailOtpPurpose, type EmailOtpRecord, EmailOtpStore } from "./email/EmailOtp.ts";
import {
  type Identifier,
  IdentifierStore,
  type IdentifierType,
  replaceInputError,
} from "./Identifier.ts";
import { type EmailVerification, EmailVerificationStore } from "./email/EmailVerification.ts";
import { MagicLinkStore, type MagicLinkToken } from "./MagicLink.ts";
import { type OAuthState, OAuthStateStore } from "./oauth/OAuth.ts";
import { PasswordResetStore, type PasswordResetToken } from "./password/PasswordReset.ts";
import { type RateLimitEntry, RateLimitStore } from "./RateLimit.ts";
import { type PendingMultiFactor, PendingMultiFactorStore } from "./multifactor/MultiFactor.ts";
import {
  ChallengeStore,
  isWebAuthnCeremony,
  type WebAuthnChallenge,
} from "./multifactor/WebAuthn.ts";
import { type GoogleOneTapNonceEntry, GoogleOneTapNonceStore } from "./GoogleOneTap.ts";
import type { OtpFailures } from "./Types.ts";

// ---------------------------------------------------------------------------
// Codecs & helpers
// ---------------------------------------------------------------------------

const toAuthError =
  (label: string) =>
  (cause: unknown): Errors.AuthError =>
    new Errors.AuthError({
      message: `KeyValueStore ${label} failed${
        P.hasProperty(cause, "message") && P.isString(cause.message) ? `: ${cause.message}` : ""
      }`,
      cause,
    });

const toBase64 = (bytes: Uint8Array): string => Base64.encode(bytes);
/** Bytes this module wrote with {@link toBase64}; a corrupted value decodes to no bytes. */
const fromBase64 = (text: string): Uint8Array =>
  Result.getOrElse(Base64.decode(text), () => new Uint8Array(0));

/** Any JSON value to and from its JSON text; record shapes are this module's own. */
const JsonText = Schema.fromJsonString(Schema.Unknown);
const decodeJsonText = Schema.decodeEffect(JsonText);
const encodeJsonText = Schema.encodeSync(JsonText);

/**
 * The member an expiring entry's JSON carries beside its `value`: the epoch-ms
 * instant after which the entry counts for nothing. No record shape in this
 * module has a member of that name, so an entry without it is a bare record
 * (one written before envelopes, or one that never expires).
 */
const EXPIRES_AT = "~expiresAt";

/** A decoded entry: its value, and its expiry when it was written with one. */
interface StoredEntry<A> {
  readonly value: A;
  readonly expiresAt: number | undefined;
}

/** An entry's JSON as `writeExpiring` writes it. */
const isEnvelope = Schema.is(Schema.Struct({ [EXPIRES_AT]: Schema.Finite, value: Schema.Unknown }));

/**
 * Small JSON codec over a raw {@link KeyValueStore.KeyValueStore}, mapping
 * storage failures to {@link Errors.AuthError}.
 *
 * `writeExpiring` wraps the record in an expiry envelope that `read` opens:
 * `KeyValueStore` has no per-entry TTL, so the envelope is what tells
 * {@link purgeExpiredKV} an entry is spent, whatever its record shape.
 */
/** A stored JSON text, or `undefined` for a miss, with its envelope opened. */
const decodeEntry = <A>(
  value: string | undefined,
  label: string,
): Effect.Effect<StoredEntry<A> | null, Errors.AuthError> =>
  value === undefined
    ? Effect.succeed(null)
    : decodeJsonText(value).pipe(
        // SAFETY: every key is namespaced to one record shape and written
        // only by `write` / `writeExpiring` with a value of that shape, so the
        // JSON under a key round-trips to the `A` its caller wrote there.
        Effect.map((parsed): StoredEntry<A> =>
          isEnvelope(parsed)
            ? { value: parsed.value as A, expiresAt: parsed[EXPIRES_AT] }
            : { value: parsed as A, expiresAt: undefined },
        ),
        Effect.mapError(toAuthError(label)),
      );

const jsonKv = (kv: KeyValueStore.KeyValueStore) => {
  /** The entry under `key`, expired or not, with its envelope opened. */
  const readEntry = <A>(
    key: string,
    label: string,
  ): Effect.Effect<StoredEntry<A> | null, Errors.AuthError> =>
    kv.get(key).pipe(
      Effect.mapError(toAuthError(label)),
      Effect.flatMap((value) => decodeEntry<A>(value, label)),
    );

  /**
   * The record under `key`, or `null`. An entry past its envelope's expiry is
   * still returned: stores are dumb persistence, and the services judge expiry
   * from the record itself, as they do over every other store.
   */
  const read = <A>(key: string, label: string): Effect.Effect<A | null, Errors.AuthError> =>
    readEntry<A>(key, label).pipe(Effect.map((entry) => (entry === null ? null : entry.value)));

  const write = (
    key: string,
    value: object | string,
    label: string,
  ): Effect.Effect<void, Errors.AuthError> =>
    kv.set(key, encodeJsonText(value)).pipe(Effect.mapError(toAuthError(label)));

  /** Write `value` in an envelope that expires after `expiresAt` (epoch ms). */
  const writeExpiring = (
    key: string,
    value: object,
    expiresAt: number,
    label: string,
  ): Effect.Effect<void, Errors.AuthError> => write(key, { [EXPIRES_AT]: expiresAt, value }, label);

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
        return Arr.match(next, {
          onEmpty: () => remove(key, label),
          onNonEmpty: (remaining) => write(key, remaining, label),
        });
      }),
    );

  return { readEntry, read, write, writeExpiring, remove, readIndex, indexAdd, indexRemove };
};

/**
 * An atomic get-and-delete over the same backend as the `KeyValueStore`
 * (Redis `GETDEL`, a Durable Object, a `DELETE … RETURNING`), for the
 * single-use stores' `consume`.
 *
 * A `KeyValueStore` has no get-and-delete, so without this service each
 * `*StoreKV` `consume` runs its read and remove under a semaphore the store
 * owns: atomic within one process, but behind several instances sharing one
 * backend, two of them can both read a record before either removes it.
 * Provide this service where the stores are built and their `consume` takes
 * the record with one `take` call instead, which holds across processes.
 *
 * `take(key)` deletes the value under `key` and returns it, or returns
 * `undefined` when there is none, as one indivisible operation: of two
 * concurrent calls with one key, at most one receives the value. It must name
 * keys as the `KeyValueStore` does: behind a `KeyValueStore.prefix` view, add
 * that prefix before calling the backend.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * // A Redis client's `getDel`, standing in for a host's binding.
 * const redis = new Map([["oauth-state:s1", "{}"]])
 * const getDel = async (key: string) => {
 *   const value = redis.get(key)
 *   redis.delete(key)
 *   return value ?? null
 * }
 *
 * const TakeLive = Layer.succeed(Auth.KeyValueStoreTake, {
 *   take: (key) =>
 *     Effect.tryPromise({
 *       try: async () => (await getDel(key)) ?? undefined,
 *       catch: (cause) => new Auth.AuthError({ message: "GETDEL failed", cause }),
 *     }),
 * })
 *
 * const program = Effect.gen(function* () {
 *   const { take } = yield* Auth.KeyValueStoreTake
 *   return [yield* take("oauth-state:s1"), yield* take("oauth-state:s1")]
 * })
 * assert.deepEqual(await Effect.runPromise(program.pipe(Effect.provide(TakeLive))), [
 *   "{}",
 *   undefined,
 * ])
 * ```
 *
 * @since 0.1.0
 * @category services
 */
export class KeyValueStoreTake extends Context.Service<
  KeyValueStoreTake,
  {
    /** Delete the value under `key` and return it, as one indivisible step. */
    readonly take: (key: string) => Effect.Effect<string | undefined, Errors.AuthError>;
  }
>()("@effect-auth/KeyValueStoreTake") {}

/**
 * The ambient `KeyValueStore` and the {@link KeyValueStoreTake}, when one is
 * provided, for building the single-use stores.
 */
const singleUseContext = Effect.all(
  {
    store: Effect.service(KeyValueStore.KeyValueStore),
    take: Effect.serviceOption(KeyValueStoreTake),
  },
  { concurrency: 1 },
);

/**
 * A single-use store's spend of the record under a key: one
 * {@link KeyValueStoreTake} call when the service is provided, otherwise its
 * read and remove under one permit of a semaphore the store owns, so within
 * one process two concurrent callers never both receive the record.
 */
const makeTakeRecord = (
  store: KeyValueStore.KeyValueStore,
  take: Option.Option<typeof KeyValueStoreTake.Service>,
) => {
  const kv = jsonKv(store);
  const lock = Semaphore.makeUnsafe(1);
  return <A>(key: string, label: string): Effect.Effect<A | null, Errors.AuthError> =>
    Option.match(take, {
      onSome: (service) =>
        service.take(key).pipe(
          Effect.flatMap((value) => decodeEntry<A>(value, label)),
          Effect.map((entry) => (entry === null ? null : entry.value)),
        ),
      onNone: () =>
        lock.withPermit(
          kv
            .read<A>(key, label)
            .pipe(Effect.tap((found) => (found === null ? Effect.void : kv.remove(key, label)))),
        ),
    });
};

// ---------------------------------------------------------------------------
// OAuthStateStore
// ---------------------------------------------------------------------------

const oauthStateKey = (state: string) => `oauth-state:${state}`;

/**
 * Build an {@link OAuthStateStore} over the ambient `KeyValueStore`.
 *
 * `consume` takes the state with one {@link KeyValueStoreTake} call when that
 * service is provided where the store is built, which holds across
 * instances sharing one backend. Without it, `consume` is the read and the
 * remove under one permit of a semaphore this store owns: two concurrent
 * callers in one process never both receive a state, but two instances
 * sharing a backend can, so this store is then single-instance only. Behind
 * several instances, provide a `KeyValueStoreTake` or use `./sql`'s store
 * (`DELETE ... RETURNING`, D1 included).
 */
export const oauthStateStoreKV: Effect.Effect<
  typeof OAuthStateStore.Service,
  never,
  KeyValueStore.KeyValueStore
> = Effect.map(singleUseContext, ({ store, take }) => {
  const kv = jsonKv(store);
  const takeRecord = makeTakeRecord(store, take);
  return {
    create: (state) =>
      kv
        .writeExpiring(oauthStateKey(state.state), state, state.expiresAt, "oauthState.create")
        .pipe(Effect.as(state)),
    consume: (state) => takeRecord<OAuthState>(oauthStateKey(state), "oauthState.consume"),
  } satisfies typeof OAuthStateStore.Service;
});

/**
 * `OAuthStateStore` layer backed by `KeyValueStore`.
 */
export const OAuthStateStoreKV: Layer.Layer<OAuthStateStore, never, KeyValueStore.KeyValueStore> =
  Layer.effect(OAuthStateStore, oauthStateStoreKV);

// ---------------------------------------------------------------------------
// WebAuthn ChallengeStore
// ---------------------------------------------------------------------------

/**
 * JSON-safe encoding of a {@link WebAuthnChallenge} (bytes as base64). An
 * entry written before ceremonies were recorded has no `ceremony`.
 */
interface StoredChallenge {
  readonly challenge: string;
  readonly ceremony?: unknown;
  readonly expiresAt: number;
  readonly userId?: string;
}

const challengeKey = (challenge: Uint8Array) => `webauthn-challenge:${toBase64(challenge)}`;

/** A stored challenge without a known ceremony reads as missing, so no ceremony redeems it. */
const decodeChallenge = (stored: StoredChallenge): WebAuthnChallenge | null =>
  isWebAuthnCeremony(stored.ceremony)
    ? {
        challenge: fromBase64(stored.challenge),
        ceremony: stored.ceremony,
        expiresAt: stored.expiresAt,
        ...(stored.userId !== undefined ? { userId: stored.userId } : {}),
      }
    : null;

/**
 * Build a WebAuthn {@link ChallengeStore} over the ambient `KeyValueStore`.
 */
export const challengeStoreKV: Effect.Effect<
  typeof ChallengeStore.Service,
  never,
  KeyValueStore.KeyValueStore
> = KeyValueStore.KeyValueStore.useSync((store) => {
  const kv = jsonKv(store);
  return {
    create: (challenge) =>
      kv
        .writeExpiring(
          challengeKey(challenge.challenge),
          {
            challenge: toBase64(challenge.challenge),
            ceremony: challenge.ceremony,
            expiresAt: challenge.expiresAt,
            ...(challenge.userId !== undefined ? { userId: challenge.userId } : {}),
          } satisfies StoredChallenge,
          challenge.expiresAt,
          "challenge.create",
        )
        .pipe(Effect.as(challenge)),
    get: (challenge) =>
      kv
        .read<StoredChallenge>(challengeKey(challenge), "challenge.get")
        .pipe(Effect.map((stored) => (stored ? decodeChallenge(stored) : null))),
    delete: (challenge) => kv.remove(challengeKey(challenge), "challenge.delete"),
  } satisfies typeof ChallengeStore.Service;
});

/**
 * WebAuthn `ChallengeStore` layer backed by `KeyValueStore`.
 */
export const ChallengeStoreKV: Layer.Layer<ChallengeStore, never, KeyValueStore.KeyValueStore> =
  Layer.effect(ChallengeStore, challengeStoreKV);

// ---------------------------------------------------------------------------
// RateLimitStore
// ---------------------------------------------------------------------------

const rateLimitKey = (key: string) => `rate-limit:${key}`;

/** When an entry stops counting: its window, its block and `until`, whichever ends last. */
const rateLimitExpiry = (entry: RateLimitEntry, until: number): number =>
  Math.max(entry.resetAt, entry.blockedUntil ?? 0, until);

/**
 * Build a {@link RateLimitStore} over the ambient `KeyValueStore`.
 *
 * **Development and single-process use only**:
 * `increment` is read-modify-write, so across processes parallel requests
 * share a count and overshoot the limit. In production use `./sql` or
 * another store with an atomic increment.
 *
 * The `ttl` arguments are honoured logically via each entry's `resetAt`
 * rather than by backend-level expiry, since `KeyValueStore` has no TTL API:
 * `set` takes a key and a value only. An entry therefore stays until
 * {@link purgeExpiredKV} deletes it once its window and block have both
 * passed.
 */
export const rateLimitStoreKV: Effect.Effect<
  typeof RateLimitStore.Service,
  never,
  KeyValueStore.KeyValueStore
> = KeyValueStore.KeyValueStore.useSync((store) => {
  const kv = jsonKv(store);
  const readEntry = (key: string) => kv.read<RateLimitEntry>(rateLimitKey(key), "rateLimit.get");
  return {
    get: readEntry,
    set: (key, entry, ttl) =>
      Effect.flatMap(Clock.currentTimeMillis, (now) =>
        kv.writeExpiring(
          rateLimitKey(key),
          entry,
          rateLimitExpiry(entry, now + ttl * 1000),
          "rateLimit.set",
        ),
      ),
    increment: (key, ttlSeconds) =>
      Effect.gen(function* () {
        const now = yield* Clock.currentTimeMillis;
        const existing = yield* readEntry(key);
        if (existing == null || now >= existing.resetAt) {
          const entry: RateLimitEntry = { key, count: 1, resetAt: now + ttlSeconds * 1000 };
          yield* kv.writeExpiring(rateLimitKey(key), entry, entry.resetAt, "rateLimit.increment");
          return 1;
        }
        const updated: RateLimitEntry = { ...existing, count: existing.count + 1 };
        yield* kv.writeExpiring(
          rateLimitKey(key),
          updated,
          rateLimitExpiry(updated, updated.resetAt),
          "rateLimit.increment",
        );
        return updated.count;
      }),
    delete: (key) => kv.remove(rateLimitKey(key), "rateLimit.delete"),
  } satisfies typeof RateLimitStore.Service;
});

/**
 * `RateLimitStore` layer backed by `KeyValueStore`. Development and
 * single-process use only; see {@link rateLimitStoreKV}.
 */
export const RateLimitStoreKV: Layer.Layer<RateLimitStore, never, KeyValueStore.KeyValueStore> =
  Layer.effect(RateLimitStore, rateLimitStoreKV);

// ---------------------------------------------------------------------------
// EmailVerificationStore
// ---------------------------------------------------------------------------

const emailVerificationTokenKey = (token: string) => `email-verification:token:${token}`;
const emailVerificationUserKey = (userId: string) => `email-verification:user:${userId}`;
const verificationByCreatedAt: Order.Order<EmailVerification> = Order.mapInput(
  Order.Number,
  (verification) => verification.createdAt,
);

/**
 * Build an {@link EmailVerificationStore} over the ambient `KeyValueStore`.
 *
 * `deleteByUserId` is served by a secondary index key per user holding the
 * user's live tokens, which {@link purgeExpiredKV} prunes as it deletes them.
 */
export const emailVerificationStoreKV: Effect.Effect<
  typeof EmailVerificationStore.Service,
  never,
  KeyValueStore.KeyValueStore
> = Effect.map(singleUseContext, ({ store, take }) => {
  const kv = jsonKv(store);
  const takeRecord = makeTakeRecord(store, take);
  const self = {
    create: (verification) =>
      Effect.gen(function* () {
        yield* kv.writeExpiring(
          emailVerificationTokenKey(verification.token),
          verification,
          verification.expiresAt,
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
          { concurrency: 1, discard: true },
        );
        yield* kv.remove(emailVerificationUserKey(userId), "emailVerification.deleteByUserId");
      }),
    getLatestByUserId: (userId) =>
      Effect.gen(function* () {
        const tokens = yield* kv.readIndex(
          emailVerificationUserKey(userId),
          "emailVerification.getLatestByUserId",
        );
        const records = yield* Effect.forEach(
          tokens,
          (token) =>
            kv.read<EmailVerification>(
              emailVerificationTokenKey(token),
              "emailVerification.getLatestByUserId",
            ),
          { concurrency: 1 },
        );
        // A stale index entry reads as a miss and is skipped.
        const live = Arr.filter(records, P.isNotNullish);
        return Arr.isReadonlyArrayNonEmpty(live) ? Arr.max(live, verificationByCreatedAt) : null;
      }),
  } satisfies Omit<typeof EmailVerificationStore.Service, "consume">;
  return {
    ...self,
    consume: (token) =>
      takeRecord<EmailVerification>(
        emailVerificationTokenKey(token),
        "emailVerification.consume",
      ).pipe(
        Effect.tap((taken) =>
          taken === null
            ? Effect.void
            : kv.indexRemove(
                emailVerificationUserKey(taken.userId),
                token,
                "emailVerification.consume",
              ),
        ),
      ),
  } satisfies typeof EmailVerificationStore.Service;
});

/**
 * `EmailVerificationStore` layer backed by `KeyValueStore`.
 */
export const EmailVerificationStoreKV: Layer.Layer<
  EmailVerificationStore,
  never,
  KeyValueStore.KeyValueStore
> = Layer.effect(EmailVerificationStore, emailVerificationStoreKV);

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
export const passwordResetStoreKV: Effect.Effect<
  typeof PasswordResetStore.Service,
  never,
  KeyValueStore.KeyValueStore
> = Effect.map(singleUseContext, ({ store, take }) => {
  const kv = jsonKv(store);
  const takeRecord = makeTakeRecord(store, take);
  const self = {
    create: (reset) =>
      Effect.gen(function* () {
        yield* kv.writeExpiring(
          passwordResetTokenKey(reset.token),
          reset,
          reset.expiresAt,
          "passwordReset.create",
        );
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
          { concurrency: 1, discard: true },
        );
        yield* kv.remove(passwordResetUserKey(userId), "passwordReset.deleteByUserId");
      }),
  } satisfies Omit<typeof PasswordResetStore.Service, "consume">;
  return {
    ...self,
    consume: (token) =>
      takeRecord<PasswordResetToken>(passwordResetTokenKey(token), "passwordReset.consume").pipe(
        Effect.tap((taken) =>
          taken === null
            ? Effect.void
            : kv.indexRemove(passwordResetUserKey(taken.userId), token, "passwordReset.consume"),
        ),
      ),
  } satisfies typeof PasswordResetStore.Service;
});

/**
 * `PasswordResetStore` layer backed by `KeyValueStore`.
 */
export const PasswordResetStoreKV: Layer.Layer<
  PasswordResetStore,
  never,
  KeyValueStore.KeyValueStore
> = Layer.effect(PasswordResetStore, passwordResetStoreKV);

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
export const magicLinkStoreKV: Effect.Effect<
  typeof MagicLinkStore.Service,
  never,
  KeyValueStore.KeyValueStore
> = Effect.map(singleUseContext, ({ store, take }) => {
  const kv = jsonKv(store);
  const takeRecord = makeTakeRecord(store, take);
  const self = {
    create: (token) =>
      Effect.gen(function* () {
        yield* kv.writeExpiring(
          magicLinkTokenKey(token.token),
          token,
          token.expiresAt,
          "magicLink.create",
        );
        yield* kv.indexAdd(magicLinkEmailKey(token.email), token.token, "magicLink.create");
        return token;
      }),
    get: (token) => kv.read<MagicLinkToken>(magicLinkTokenKey(token), "magicLink.get"),
    getByEmail: (email) =>
      Effect.gen(function* () {
        const tokens = yield* kv.readIndex(magicLinkEmailKey(email), "magicLink.getByEmail");
        const latest = Arr.last(tokens);
        if (Option.isNone(latest)) return null;
        return yield* kv.read<MagicLinkToken>(
          magicLinkTokenKey(latest.value),
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
          { concurrency: 1, discard: true },
        );
        yield* kv.remove(magicLinkEmailKey(email), "magicLink.deleteByEmail");
      }),
  } satisfies Omit<typeof MagicLinkStore.Service, "consume">;
  return {
    ...self,
    consume: (token) =>
      takeRecord<MagicLinkToken>(magicLinkTokenKey(token), "magicLink.consume").pipe(
        Effect.tap((taken) =>
          taken === null
            ? Effect.void
            : kv.indexRemove(magicLinkEmailKey(taken.email), token, "magicLink.consume"),
        ),
      ),
  } satisfies typeof MagicLinkStore.Service;
});

/**
 * `MagicLinkStore` layer backed by `KeyValueStore`.
 */
export const MagicLinkStoreKV: Layer.Layer<MagicLinkStore, never, KeyValueStore.KeyValueStore> =
  Layer.effect(MagicLinkStore, magicLinkStoreKV);

// ---------------------------------------------------------------------------
// EmailOtpStore
// ---------------------------------------------------------------------------

const emailOtpKey = (email: string, purpose: EmailOtpPurpose) => `email-otp:${purpose}:${email}`;
/** The pair's failure budget: a key of its own, outside the `email-otp:` prefix the codes live under. */
const emailOtpFailuresKey = (email: string, purpose: EmailOtpPurpose) =>
  `email-otp-failures:${purpose}:${email}`;

/**
 * Build an {@link EmailOtpStore} over the ambient `KeyValueStore`.
 *
 * There is at most one active OTP per email + purpose pair, so the pair is
 * the key itself and no secondary index is needed. The pair's failure budget
 * lives under its own `email-otp-failures:` key, so replacing or
 * deleting the OTP leaves it; `clearFailures` removes it, and
 * {@link purgeExpiredKV} once its backoff has long decayed.
 *
 * **Development and single-process use only**: its
 * counts are read-modify-write, so across processes parallel attempts share
 * a count. In production use `./sql` or another store with atomic counters.
 */
export const emailOtpStoreKV: Effect.Effect<
  typeof EmailOtpStore.Service,
  never,
  KeyValueStore.KeyValueStore
> = KeyValueStore.KeyValueStore.useSync((store) => {
  const kv = jsonKv(store);
  const attemptsLock = Semaphore.makeUnsafe(1);
  return {
    upsert: (record) =>
      kv
        .writeExpiring(
          emailOtpKey(record.email, record.purpose),
          record,
          record.expiresAt,
          "emailOtp.upsert",
        )
        .pipe(Effect.as(record)),
    get: (email, purpose) => kv.read<EmailOtpRecord>(emailOtpKey(email, purpose), "emailOtp.get"),
    delete: (email, purpose) => kv.remove(emailOtpKey(email, purpose), "emailOtp.delete"),
    incrementAttempts: (email, purpose) =>
      attemptsLock.withPermit(
        Effect.gen(function* () {
          const record = yield* kv.read<EmailOtpRecord>(
            emailOtpKey(email, purpose),
            "emailOtp.incrementAttempts",
          );
          if (record == null) return null;
          const updated: EmailOtpRecord = { ...record, attempts: record.attempts + 1 };
          yield* kv.writeExpiring(
            emailOtpKey(email, purpose),
            updated,
            updated.expiresAt,
            "emailOtp.incrementAttempts",
          );
          return updated.attempts;
        }),
      ),
    getFailures: (email, purpose) =>
      kv.read<OtpFailures>(emailOtpFailuresKey(email, purpose), "emailOtp.getFailures"),
    recordFailure: (email, purpose, at) =>
      Effect.gen(function* () {
        const key = emailOtpFailuresKey(email, purpose);
        const stored = yield* kv.read<OtpFailures>(key, "emailOtp.recordFailure");
        const failures: OtpFailures = { count: (stored?.count ?? 0) + 1, lastFailureAt: at };
        yield* kv.write(key, failures, "emailOtp.recordFailure");
        return failures;
      }),
    clearFailures: (email, purpose) =>
      kv.remove(emailOtpFailuresKey(email, purpose), "emailOtp.clearFailures"),
  } satisfies typeof EmailOtpStore.Service;
});

/**
 * `EmailOtpStore` layer backed by `KeyValueStore`. Development and
 * single-process use only; see {@link emailOtpStoreKV}.
 */
export const EmailOtpStoreKV: Layer.Layer<EmailOtpStore, never, KeyValueStore.KeyValueStore> =
  Layer.effect(EmailOtpStore, emailOtpStoreKV);

// ---------------------------------------------------------------------------
// purgeExpiredKV
// ---------------------------------------------------------------------------

/**
 * An optional prefix listing for {@link purgeExpiredKV}, for a backend that
 * lists by prefix more cheaply than it lists everything.
 *
 * Without it, the purge reads the `KeyValueStore`'s own `keys` (every key, new
 * in Effect 4.1) and keeps those under each prefix it purges. That is enough
 * for the in-memory, file-system, SQL and browser-storage stores. Provide this
 * when the store's namespace is large or shared and the backend can list one
 * prefix: Workers KV `list({ prefix })` followed through every `cursor`, Redis
 * `SCAN … MATCH prefix*`.
 *
 * `list(prefix)` returns every key that starts with `prefix`, exactly as the
 * `KeyValueStore` sees it: when the store is a `KeyValueStore.prefix` view,
 * strip that prefix from the backend's keys. A key listed but gone by the
 * time it is read is skipped, so a listing need not be a snapshot.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * // A host's binding, here a fixed key list standing in for a backend.
 * const keys = ["email-otp:sign-in:a@example.com", "oauth-state:s1"]
 * const KeysLive = Layer.succeed(Auth.KeyValueStoreKeys, {
 *   list: (prefix) => Effect.succeed(keys.filter((key) => key.startsWith(prefix))),
 * })
 *
 * const program = Effect.gen(function* () {
 *   const listing = yield* Auth.KeyValueStoreKeys
 *   return yield* listing.list("email-otp:")
 * })
 * assert.deepEqual(await Effect.runPromise(program.pipe(Effect.provide(KeysLive))), [
 *   "email-otp:sign-in:a@example.com",
 * ])
 * ```
 */
export class KeyValueStoreKeys extends Context.Service<
  KeyValueStoreKeys,
  {
    /** Every key starting with `prefix`, as the `KeyValueStore` names it. */
    readonly list: (prefix: string) => Effect.Effect<ReadonlyArray<string>, Errors.AuthError>;
  }
>()("@effect-auth/KeyValueStoreKeys") {}

/**
 * An in-memory `KeyValueStore` together with the {@link KeyValueStoreKeys}
 * listing and the {@link KeyValueStoreTake} over the same map, for tests,
 * examples and single-process demos. Each build of the layer starts empty.
 * `KeyValueStore.layerMemory` serves {@link purgeExpiredKV} too (through its
 * `keys`); this layer also provides the listing, for code that reads it.
 */
export const layerMemoryKeyValueStore: Layer.Layer<
  KeyValueStore.KeyValueStore | KeyValueStoreKeys | KeyValueStoreTake
> = Layer.unwrap(
  Effect.sync(() => {
    const entries = MutableHashMap.empty<string, string>();
    return Layer.mergeAll(
      Layer.succeed(
        KeyValueStore.KeyValueStore,
        KeyValueStore.makeStringOnly({
          get: (key) => Effect.sync(() => Option.getOrUndefined(MutableHashMap.get(entries, key))),
          set: (key, value) => Effect.sync(() => void MutableHashMap.set(entries, key, value)),
          remove: (key) => Effect.sync(() => void MutableHashMap.remove(entries, key)),
          clear: Effect.sync(() => void MutableHashMap.clear(entries)),
          size: Effect.sync(() => MutableHashMap.size(entries)),
          keys: Effect.sync(() => Arr.fromIterable(MutableHashMap.keys(entries))),
        }),
      ),
      Layer.succeed(KeyValueStoreKeys, {
        list: (prefix) =>
          Effect.sync(() =>
            Arr.filter(Arr.fromIterable(MutableHashMap.keys(entries)), (key) =>
              key.startsWith(prefix),
            ),
          ),
      }),
      Layer.succeed(KeyValueStoreTake, {
        take: (key) =>
          Effect.sync(() => {
            const value = Option.getOrUndefined(MutableHashMap.get(entries, key));
            MutableHashMap.remove(entries, key);
            return value;
          }),
      }),
    );
  }),
);

/**
 * How many expired records one {@link purgeExpiredKV} run deleted, per store.
 */
export interface PurgeExpiredKVResult {
  /** OAuth states deleted (`OAuthStateStoreKV`). */
  readonly oauthStates: number;
  /** WebAuthn challenges deleted (`ChallengeStoreKV`). */
  readonly webauthnChallenges: number;
  /** Pending second-factor challenges deleted, with their counts (`PendingMultiFactorStoreKV`). */
  readonly pendingMultiFactor: number;
  /** Email verification tokens deleted (`EmailVerificationStoreKV`). */
  readonly emailVerifications: number;
  /** Password reset tokens deleted (`PasswordResetStoreKV`). */
  readonly passwordResets: number;
  /** Magic-link tokens deleted (`MagicLinkStoreKV`). */
  readonly magicLinks: number;
  /** Email OTP records deleted (`EmailOtpStoreKV`). */
  readonly emailOtps: number;
  /** Email OTP failure budgets deleted (`EmailOtpStoreKV`): no wrong code for `otpFailureRetention`. */
  readonly emailOtpFailures: number;
  /** Rate-limit entries deleted (`RateLimitStoreKV`): their window, block and TTL have all passed. */
  readonly rateLimits: number;
  /** Google One Tap nonces deleted (`GoogleOneTapNonceStoreKV`). */
  readonly googleOneTapNonces: number;
}

/** Options for {@link purgeExpiredKVWith}. */
export interface PurgeExpiredKVOptions {
  /**
   * How long an email-OTP failure budget outlives its latest wrong code.
   * Default 25 hours: the default backoff cap (`backoff.maxDelay`, a day) and
   * an hour's margin. Keep it at least your `maxDelay`.
   */
  readonly otpFailureRetention?: Duration.Input | undefined;
}

/** The listing a store's own `keys` gives: every key, kept under `prefix`. */
const storeKeys = (store: KeyValueStore.KeyValueStore): typeof KeyValueStoreKeys.Service => ({
  list: (prefix) =>
    store.keys.pipe(
      Effect.map(Arr.filter((key) => key.startsWith(prefix))),
      Effect.mapError(
        (cause) => new Errors.AuthError({ message: "KeyValueStore keys failed", cause }),
      ),
    ),
});

/**
 * The services refuse a record once `now > expiresAt`, so an entry whose
 * expiry is `now` is still live and stays. The envelope's expiry is the
 * record's own `expiresAt`; an entry written before envelopes has only the
 * record's.
 */
const hasExpired =
  (now: number) =>
  (entry: StoredEntry<{ readonly expiresAt: number }>): boolean =>
    (entry.expiresAt ?? entry.value.expiresAt) < now;

/**
 * `RateLimiter` opens a fresh window once `now >= resetAt` and lifts a block
 * once `now >= blockedUntil`, so an entry past both counts for nothing: the
 * limiter treats its key as one it has never seen (as `./sql`'s does). The
 * envelope also carries the TTL `set` was given, which the entry outlives too.
 */
const isSpentRateLimit =
  (now: number) =>
  ({ value: entry, expiresAt }: StoredEntry<RateLimitEntry>): boolean =>
    entry.resetAt <= now &&
    (entry.blockedUntil === undefined || entry.blockedUntil <= now) &&
    (expiresAt === undefined || expiresAt <= now);

const purgeExpiredRecords = <A>(options: {
  readonly kv: ReturnType<typeof jsonKv>;
  readonly keys: typeof KeyValueStoreKeys.Service;
  readonly prefix: string;
  readonly label: string;
  /** Whether the entry can go: the services would no longer honour it. */
  readonly isPurgeable: (entry: StoredEntry<A>) => boolean;
  readonly onRemoved?: ((record: A) => Effect.Effect<void, Errors.AuthError>) | undefined;
}): Effect.Effect<number, Errors.AuthError> =>
  options.keys.list(options.prefix).pipe(
    Effect.flatMap((keys) =>
      Effect.reduce(
        keys,
        () => 0,
        (removed, key) =>
          Effect.gen(function* () {
            const entry = yield* options.kv.readEntry<A>(key, options.label);
            if (entry == null || !options.isPurgeable(entry)) return removed;
            yield* options.kv.remove(key, options.label);
            if (options.onRemoved !== undefined) yield* options.onRemoved(entry.value);
            return removed + 1;
          }),
      ),
    ),
  );

/**
 * Delete every expired record from the `KeyValueStore`-backed stores (the
 * `*StoreKV` layers, and so `layerKV` and the testing package's
 * `memoryStores`); requires the `KeyValueStore`. It finds the records through
 * {@link KeyValueStoreKeys} when one is provided, and through the store's own
 * `keys` otherwise, and reads only the prefixes those stores write, so a
 * namespace shared with other data loses nothing else.
 *
 * `KeyValueStore` has no per-entry expiry, so no record goes on its own, and
 * most are written for unauthenticated requests: an OAuth state per authorize
 * redirect, a WebAuthn challenge per begin, a rate-limit entry per key counted,
 * a code or link per send. Schedule this from the host (a cron trigger on
 * Workers, a timer on a long-lived server) so the store stays bounded. Expiry
 * is read from the `Clock`, and a purge changes no outcome:
 *
 * - An OAuth state, WebAuthn challenge, pending second factor (its failure
 *   count with it), email verification, password reset, magic link, email OTP
 *   or One Tap nonce goes once its expiry is before now; the services already
 *   refuse it. A deleted token also leaves its user's or address's index.
 * - A rate-limit entry goes once its `resetAt`, its `blockedUntil` and the TTL
 *   it was `set` with are all not after now: the limiter then treats the key as
 *   one it has never seen.
 * - An email-OTP failure budget goes once its latest wrong code is
 *   `otpFailureRetention` old ({@link purgeExpiredKVWith}): past the backoff
 *   cap the delay has fully decayed.
 *
 * Like the stores' other multi-step writes, this is read-then-delete, not
 * atomic: an OTP re-sent for the same address and
 * purpose between the read and the delete is deleted too, so that code is
 * refused and the user asks for another. That fails closed.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Layer } from "effect"
 * import { TestClock } from "effect/testing"
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * const StoresLive = Layer.provideMerge(
 *   Layer.merge(Auth.MagicLinkStoreKV, Auth.EmailOtpStoreKV),
 *   Auth.layerMemoryKeyValueStore,
 * )
 *
 * const program = Effect.gen(function* () {
 *   yield* TestClock.setTime(10_000)
 *   const otps = yield* Auth.Email.EmailOtpStore
 *   const record = {
 *     email: "a@example.com",
 *     otpHash: "hash",
 *     attempts: 0,
 *     createdAt: 0,
 *   }
 *   yield* otps.upsert({ ...record, purpose: "sign-in", expiresAt: 5_000 })
 *   yield* otps.upsert({ ...record, purpose: "forget-password", expiresAt: 60_000 })
 *
 *   const purged = yield* Auth.purgeExpiredKV
 *   assert.equal(purged.emailOtps, 1)
 *   assert.equal(yield* otps.get("a@example.com", "sign-in"), null)
 *   assert.notEqual(yield* otps.get("a@example.com", "forget-password"), null)
 * })
 *
 * await Effect.runPromise(
 *   program.pipe(Effect.provide(Layer.merge(StoresLive, TestClock.layer()))),
 * )
 * ```
 */
export const purgeExpiredKV: Effect.Effect<
  PurgeExpiredKVResult,
  Errors.AuthError,
  KeyValueStore.KeyValueStore
> = Effect.suspend(() => purgeExpiredKVWith());

/** {@link PurgeExpiredKVOptions.otpFailureRetention}'s default. */
export const DEFAULT_KV_OTP_FAILURE_RETENTION: Duration.Duration = Duration.hours(25);

/**
 * {@link purgeExpiredKV} with options; requires the `KeyValueStore`. A
 * retention that is negative or infinite fails with `AuthError` before
 * anything is read.
 */
export const purgeExpiredKVWith = (
  options?: PurgeExpiredKVOptions,
): Effect.Effect<PurgeExpiredKVResult, Errors.AuthError, KeyValueStore.KeyValueStore> => {
  const retention = Duration.toMillis(
    options?.otpFailureRetention ?? DEFAULT_KV_OTP_FAILURE_RETENTION,
  );
  if (!(Number.isFinite(retention) && retention >= 0)) {
    return Effect.fail(
      new Errors.AuthError({
        message: "purgeExpiredKV otpFailureRetention must be a finite, non-negative duration",
      }),
    );
  }
  return KeyValueStore.KeyValueStore.use((store) =>
    Effect.gen(function* () {
      const listing = yield* Effect.serviceOption(KeyValueStoreKeys);
      const keys = Option.getOrElse(listing, () => storeKeys(store));
      const now = yield* Clock.currentTimeMillis;
      const kv = jsonKv(store);
      const expired = hasExpired(now);
      const purge = <A>(
        label: string,
        prefix: string,
        isPurgeable: (entry: StoredEntry<A>) => boolean,
        onRemoved?: (record: A) => Effect.Effect<void, Errors.AuthError>,
      ) =>
        purgeExpiredRecords<A>({
          kv,
          keys,
          prefix,
          label: `purgeExpired.${label}`,
          isPurgeable,
          onRemoved,
        });
      return {
        oauthStates: yield* purge<OAuthState>("oauthStates", oauthStateKey(""), expired),
        webauthnChallenges: yield* purge<StoredChallenge>(
          "webauthnChallenges",
          "webauthn-challenge:",
          expired,
        ),
        pendingMultiFactor: yield* purge<StoredPendingMultiFactor>(
          "pendingMultiFactor",
          pendingMultiFactorKey(""),
          expired,
        ),
        emailVerifications: yield* purge<EmailVerification>(
          "emailVerifications",
          emailVerificationTokenKey(""),
          expired,
          (verification) =>
            kv.indexRemove(
              emailVerificationUserKey(verification.userId),
              verification.token,
              "purgeExpired.emailVerifications",
            ),
        ),
        passwordResets: yield* purge<PasswordResetToken>(
          "passwordResets",
          passwordResetTokenKey(""),
          expired,
          (reset) =>
            kv.indexRemove(
              passwordResetUserKey(reset.userId),
              reset.token,
              "purgeExpired.passwordResets",
            ),
        ),
        magicLinks: yield* purge<MagicLinkToken>(
          "magicLinks",
          magicLinkTokenKey(""),
          expired,
          (token) =>
            kv.indexRemove(magicLinkEmailKey(token.email), token.token, "purgeExpired.magicLinks"),
        ),
        emailOtps: yield* purge<EmailOtpRecord>("emailOtps", "email-otp:", expired),
        emailOtpFailures: yield* purge<OtpFailures>(
          "emailOtpFailures",
          "email-otp-failures:",
          ({ value }) => value.lastFailureAt < now - retention,
        ),
        rateLimits: yield* purge<RateLimitEntry>(
          "rateLimits",
          rateLimitKey(""),
          isSpentRateLimit(now),
        ),
        googleOneTapNonces: yield* purge<GoogleOneTapNonceEntry>(
          "googleOneTapNonces",
          googleOneTapNonceKey(""),
          expired,
        ),
      } satisfies PurgeExpiredKVResult;
    }),
  );
};

// ---------------------------------------------------------------------------
// PendingMultiFactorStore
// ---------------------------------------------------------------------------

const pendingMultiFactorKey = (token: string) => `pending-multi-factor:${token}`;

/**
 * A pending challenge as stored: the record plus its failed-attempt count, so
 * deleting (or purging) the challenge drops the count with it. Records
 * written before the count existed read as zero attempts.
 */
interface StoredPendingMultiFactor extends PendingMultiFactor {
  readonly failedAttempts?: number | undefined;
}

const withoutAttempts = (stored: StoredPendingMultiFactor): PendingMultiFactor =>
  Struct.omit(stored, ["failedAttempts"]);

/**
 * Build a {@link PendingMultiFactorStore} over the ambient `KeyValueStore`.
 *
 * **Development and single-process use only**: its
 * counts are read-modify-write, so across processes parallel attempts share
 * a count. In production use `./sql` or another store with atomic counters.
 */
export const pendingMultiFactorStoreKV: Effect.Effect<
  typeof PendingMultiFactorStore.Service,
  never,
  KeyValueStore.KeyValueStore
> = Effect.map(singleUseContext, ({ store, take }) => {
  const kv = jsonKv(store);
  const takeRecord = makeTakeRecord(store, take);
  const attemptsLock = Semaphore.makeUnsafe(1);
  const read = (token: string, label: string) =>
    kv.read<StoredPendingMultiFactor>(pendingMultiFactorKey(token), label);
  const self = {
    create: (pending) =>
      kv
        .writeExpiring(
          pendingMultiFactorKey(pending.token),
          { ...pending, failedAttempts: 0 } satisfies StoredPendingMultiFactor,
          pending.expiresAt,
          "pendingMultiFactor.create",
        )
        .pipe(Effect.as(pending)),
    get: (token) =>
      read(token, "pendingMultiFactor.get").pipe(
        Effect.map((stored) => (stored === null ? null : withoutAttempts(stored))),
      ),
    recordFailedAttempt: (token) =>
      attemptsLock.withPermit(
        Effect.gen(function* () {
          const stored = yield* read(token, "pendingMultiFactor.recordFailedAttempt");
          if (stored === null) {
            return yield* new Errors.AuthError({
              message: "Pending multi-factor challenge not found",
            });
          }
          const failedAttempts = (stored.failedAttempts ?? 0) + 1;
          yield* kv.writeExpiring(
            pendingMultiFactorKey(token),
            { ...stored, failedAttempts },
            stored.expiresAt,
            "pendingMultiFactor.recordFailedAttempt",
          );
          return failedAttempts;
        }),
      ),
    delete: (token) => kv.remove(pendingMultiFactorKey(token), "pendingMultiFactor.delete"),
  } satisfies Omit<typeof PendingMultiFactorStore.Service, "consume">;
  return {
    ...self,
    consume: (token) =>
      takeRecord<StoredPendingMultiFactor>(
        pendingMultiFactorKey(token),
        "pendingMultiFactor.consume",
      ).pipe(Effect.map((taken) => (taken === null ? null : withoutAttempts(taken)))),
  } satisfies typeof PendingMultiFactorStore.Service;
});

/**
 * `PendingMultiFactorStore` layer backed by `KeyValueStore`. Development and
 * single-process use only; see {@link pendingMultiFactorStoreKV}.
 */
export const PendingMultiFactorStoreKV: Layer.Layer<
  PendingMultiFactorStore,
  never,
  KeyValueStore.KeyValueStore
> = Layer.effect(PendingMultiFactorStore, pendingMultiFactorStoreKV);

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
/** Oldest identifier first. */
const identifierByCreatedAt: Order.Order<Identifier> = Order.mapInput(
  Order.Date,
  (identifier: Identifier) => identifier.createdAt,
);
const identifierTypeValueKey = (type: IdentifierType, value: string) =>
  `identifier:type-value:${type}:${value}`;
const identifierUserKey = (userId: string) => `identifier:user:${userId}`;

const decodeIdentifier = (stored: StoredIdentifier): Identifier => ({
  id: stored.id,
  userId: stored.userId,
  type: stored.type,
  value: stored.value,
  verified: stored.verified,
  ...(stored.verifiedAt !== undefined
    ? { verifiedAt: DateTime.toDateUtc(DateTime.makeUnsafe(stored.verifiedAt)) }
    : {}),
  createdAt: DateTime.toDateUtc(DateTime.makeUnsafe(stored.createdAt)),
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
 * Build an {@link IdentifierStore} over the ambient `KeyValueStore`.
 *
 * **Development and single-process use only**: a
 * `KeyValueStore` has no unique index, so `create` and `replace` check that
 * a value is free with a read before they write, and two processes can both
 * claim one address. `byo-stores.md` makes a real unique constraint a must;
 * in production use `./sql` or another store with one.
 *
 * Key layout:
 * - `identifier:${id}` — primary record (full `StoredIdentifier`)
 * - `identifier:type-value:${type}:${value}` — id for `getByValue` lookups
 * - `identifier:user:${userId}` — JSON array of ids for `listByUser` /
 *   `deleteByUser`
 */
export const identifierStoreKV: Effect.Effect<
  typeof IdentifierStore.Service,
  never,
  KeyValueStore.KeyValueStore
> = KeyValueStore.KeyValueStore.useSync((store) => {
  const kv = jsonKv(store);

  const getByValue = (type: IdentifierType, value: string, label: string) =>
    Effect.gen(function* () {
      const id = yield* kv.read<string>(identifierTypeValueKey(type, value), label);
      if (id == null) return null;
      const stored = yield* kv.read<StoredIdentifier>(identifierKey(id), label);
      return stored == null ? null : decodeIdentifier(stored);
    });

  const create = (identifier: Identifier, label: string) =>
    Effect.gen(function* () {
      const stored = encodeIdentifier(identifier);
      yield* kv.write(identifierKey(identifier.id), stored, label);
      yield* kv.write(
        identifierTypeValueKey(identifier.type, identifier.value),
        identifier.id,
        label,
      );
      yield* kv.indexAdd(identifierUserKey(identifier.userId), identifier.id, label);
      return identifier;
    });

  const remove = (id: string, label: string) =>
    Effect.gen(function* () {
      const stored = yield* kv.read<StoredIdentifier>(identifierKey(id), label);
      if (stored == null) return;
      yield* kv.remove(identifierKey(id), label);
      yield* kv.remove(identifierTypeValueKey(stored.type, stored.value), label);
      yield* kv.indexRemove(identifierUserKey(stored.userId), id, label);
    });

  return {
    getByValue: (type, value) => getByValue(type, value, "identifier.getByValue"),

    listByUser: (userId) =>
      Effect.gen(function* () {
        const ids = yield* kv.readIndex(identifierUserKey(userId), "identifier.listByUser");
        const records = yield* Effect.forEach(
          ids,
          (id) => kv.read<StoredIdentifier>(identifierKey(id), "identifier.listByUser"),
          { concurrency: "unbounded" },
        );
        return Arr.sort(
          records.filter((r): r is StoredIdentifier => r != null).map(decodeIdentifier),
          identifierByCreatedAt,
        );
      }),

    // `(type, value)` is unique: a claimed pair is refused with `AuthError`, as
    // a unique index would refuse it, so `claimIdentifier` reports it as taken.
    // A read before the write, so two concurrent creates can still both land.
    create: (identifier) =>
      Effect.gen(function* () {
        if ((yield* getByValue(identifier.type, identifier.value, "identifier.create")) !== null) {
          return yield* new Errors.AuthError({
            message: `Identifier (${identifier.type}) already exists`,
          });
        }
        return yield* create(identifier, "identifier.create");
      }),

    // A KeyValueStore has no transactions: the replacement is claimed before
    // the old record is released, so a failure in between leaves the user
    // holding both, never neither. The taken-value check is a read before the
    // write, as everywhere in this store.
    replace: (from, to) =>
      Effect.gen(function* () {
        const invalid = replaceInputError(from, to);
        if (invalid !== null) return yield* invalid;
        const held = yield* kv.read<StoredIdentifier>(identifierKey(from.id), "identifier.replace");
        if (
          held == null ||
          held.userId !== from.userId ||
          held.type !== from.type ||
          held.value !== from.value
        ) {
          return null;
        }
        if ((yield* getByValue(to.type, to.value, "identifier.replace")) !== null) {
          return yield* new Errors.AuthError({
            message: `Identifier (${to.type}) already exists`,
          });
        }
        yield* create(to, "identifier.replace");
        yield* remove(from.id, "identifier.replace");
        return to;
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

    delete: (id) => remove(id, "identifier.delete"),

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
          { concurrency: 1, discard: true },
        );
        yield* kv.remove(identifierUserKey(userId), "identifier.deleteByUser");
      }),
  } satisfies typeof IdentifierStore.Service;
});

/**
 * `IdentifierStore` layer backed by `KeyValueStore`.
 *
 * Development and single-process use only; see {@link identifierStoreKV}.
 * Unlike the ephemeral stores, identifier records are long-lived, so even
 * then give it a `KeyValueStore` backend that persists data across restarts
 * (the file system, SQLite through `KeyValueStore.layerSql`).
 */
export const IdentifierStoreKV: Layer.Layer<IdentifierStore, never, KeyValueStore.KeyValueStore> =
  Layer.effect(IdentifierStore, identifierStoreKV);

// ---------------------------------------------------------------------------
// GoogleOneTapNonceStore
// ---------------------------------------------------------------------------

const googleOneTapNonceKey = (nonce: string) => `google-one-tap-nonce:${nonce}`;

/**
 * Build a {@link GoogleOneTapNonceStore} over the ambient `KeyValueStore`.
 *
 * Nonce entries are stored as JSON objects with an `expiresAt` epoch-ms field.
 * Expiry is enforced logically in `GoogleOneTap.signIn` (the entry is deleted
 * on first access regardless of validity, making every nonce single-use).
 */
export const googleOneTapNonceStoreKV: Effect.Effect<
  typeof GoogleOneTapNonceStore.Service,
  never,
  KeyValueStore.KeyValueStore
> = KeyValueStore.KeyValueStore.useSync((store) => {
  const kv = jsonKv(store);
  return {
    create: (nonce, expiresAt) =>
      kv.writeExpiring(
        googleOneTapNonceKey(nonce),
        { expiresAt } satisfies GoogleOneTapNonceEntry,
        expiresAt,
        "googleOneTapNonce.create",
      ),
    get: (nonce) =>
      kv.read<GoogleOneTapNonceEntry>(googleOneTapNonceKey(nonce), "googleOneTapNonce.get"),
    delete: (nonce) => kv.remove(googleOneTapNonceKey(nonce), "googleOneTapNonce.delete"),
  } satisfies typeof GoogleOneTapNonceStore.Service;
});

/**
 * `GoogleOneTapNonceStore` layer backed by `KeyValueStore`.
 */
export const GoogleOneTapNonceStoreKV: Layer.Layer<
  GoogleOneTapNonceStore,
  never,
  KeyValueStore.KeyValueStore
> = Layer.effect(GoogleOneTapNonceStore, googleOneTapNonceStoreKV);

// ---------------------------------------------------------------------------
// Aggregate layer
// ---------------------------------------------------------------------------

/**
 * The token and state stores, backed by the ambient `KeyValueStore`: OAuth
 * states, WebAuthn challenges, email verification, password reset and
 * magic-link tokens. This is the bundle for a deployment; it leaves out the
 * counter stores, which are single-process only ({@link layerKVSingleProcess}), so
 * provide `RateLimitStore`, `EmailOtpStore` and `PendingMultiFactorStore`
 * from `@thomasfosterau/effect-auth/sql` or another store with atomic counters.
 * {@link layerKVSingleProcess} adds the KV counter stores, for development,
 * tests and one process.
 *
 * Their single-use `consume` is atomic within one process, and across
 * processes only when a {@link KeyValueStoreTake} is provided beneath, and an
 * eventually consistent backend such as Cloudflare KV can hand
 * a spent record out again, so keep these on a strongly consistent backend.
 */
export const layerKV: Layer.Layer<
  OAuthStateStore | ChallengeStore | EmailVerificationStore | PasswordResetStore | MagicLinkStore,
  never,
  KeyValueStore.KeyValueStore
> = Layer.mergeAll(
  OAuthStateStoreKV,
  ChallengeStoreKV,
  EmailVerificationStoreKV,
  PasswordResetStoreKV,
  MagicLinkStoreKV,
);

/**
 * {@link layerKV} and the KV counter stores (`RateLimitStoreKV`,
 * `EmailOtpStoreKV`, `PendingMultiFactorStoreKV`): every ephemeral store over
 * the ambient `KeyValueStore`. **Development, tests and a single process
 * only**: across processes the counters' read-modify-write lets parallel
 * guesses share a count.
 */
export const layerKVSingleProcess: Layer.Layer<
  Layer.Success<typeof layerKV> | RateLimitStore | EmailOtpStore | PendingMultiFactorStore,
  never,
  KeyValueStore.KeyValueStore
> = Layer.mergeAll(layerKV, RateLimitStoreKV, EmailOtpStoreKV, PendingMultiFactorStoreKV);
