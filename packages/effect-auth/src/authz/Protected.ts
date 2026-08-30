/**
 * Schema-embedded authorization: policy enforcement at the data boundary.
 *
 * Effect Schema transformations carry a **Requirements** channel, so a schema
 * can demand the authorization context and decide, per field, whether the
 * current principal may see or set a value (`docs/better-auth-parity.md` §2.5,
 * decision 6 — "the Barake insight, generalized"). Wrapping a field with
 * {@link protectedField} turns a policy into two guards on the same field:
 *
 * - **Encoding** is the *viewer projection*: a principal who may not read the
 *   field simply does not receive the key (`onEncodeDeny: "redact"`, the
 *   default). Hiding beats erroring when rendering a response.
 * - **Decoding** is the *write-side guard*: a client that supplies a field it
 *   may not set is a schema error (`onDecodeDeny: "fail"`, the default), not a
 *   silent drop. Flip it to `"redact"` when ignoring the value is the friendlier
 *   contract (e.g. a permissive public API that tolerates extra input).
 *
 * A protected field is **optional-keyed**: redaction removes the key entirely
 * rather than yielding `undefined`, and an absent value is always allowed —
 * authorization asks about a *value*, and there is nothing to authorize when the
 * field is not there.
 *
 * The mechanism is one projection of the same policy kernel, not a parallel
 * one: {@link protectedField} accepts any {@link Policy.Policy} — a declarative,
 * storable, tenant-editable policy or a `Policy.custom` escape hatch — and the
 * decision is made exactly as `Authorizer` makes it (`CurrentPrincipal` +
 * an {@link EntityResolver}-resolved slice + the pure kernel).
 *
 * @example Viewer projection + write guard on one field
 * ```ts
 * import { Schema } from "effect"
 * import { Authz } from "@thomasfosterau/effect-auth"
 *
 * const UserView = Schema.Struct({
 *   id: Schema.String,
 *   email: Authz.protectedField(Schema.String, {
 *     policies: Authz.Policy.role("admin"),
 *     action: "user:read-email",
 *   }),
 * })
 *
 * // Encoding drops `email` for a principal outside Role::"admin";
 * // decoding fails when such a principal supplies it.
 * ```
 *
 * @module authz/protected
 */
import { Effect, Option, Schema, SchemaGetter, SchemaIssue } from "effect";
import { CurrentPrincipal, EntityResolver, requestRefs } from "./Authorizer.ts";
import * as Entity from "./Entity.ts";
import * as Policy from "./Policy.ts";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/**
 * What a denied decision does to the value on one direction of the codec:
 * `"redact"` omits the key, `"fail"` rejects the whole parse with a
 * `SchemaIssue.Forbidden`.
 */
export type DenyBehavior = "redact" | "fail";

/**
 * How a field is protected. `policies` may be a single policy or a set, mixing
 * declarative and custom policies freely; their requirements must already be
 * discharged (`R = never`), because a schema transformation's Requirements
 * channel is reserved for the authorization context itself.
 */
export interface ProtectedFieldOptions<E = unknown> {
  /** The policy set this field's decision is made against. */
  readonly policies: Policy.Policy<E, never> | ReadonlyArray<Policy.Policy<E, never>>;
  /**
   * The capability this field represents, e.g. `"user:read-email"`. A string is
   * lifted to `Action::"<string>"`.
   */
  readonly action: string | Entity.EntityRef;
  /**
   * The resource the field belongs to. Defaults to the **principal's own
   * reference** — the self-referential case (a user's own record), which is
   * what field-level protection usually means.
   */
  readonly resource?: Entity.EntityRef;
  /** Extra request context available to policy conditions. */
  readonly context?: Readonly<Record<string, Entity.AttributeValue>>;
  /**
   * What happens when decoding a present value the principal may not set.
   * Defaults to `"fail"`: supplying a forbidden field is a client error.
   */
  readonly onDecodeDeny?: DenyBehavior;
  /**
   * What happens when encoding a value the principal may not read. Defaults to
   * `"redact"`: a viewer projection hides, it does not error.
   */
  readonly onEncodeDeny?: DenyBehavior;
}

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

const toActionRef = (action: string | Entity.EntityRef): Entity.EntityRef =>
  typeof action === "string" ? Entity.ref("Action", action) : action;

const toPolicies = <E>(
  policies: Policy.Policy<E, never> | ReadonlyArray<Policy.Policy<E, never>>,
): ReadonlyArray<Policy.Policy<E, never>> =>
  Array.isArray(policies)
    ? (policies as ReadonlyArray<Policy.Policy<E, never>>)
    : [policies as Policy.Policy<E, never>];

/**
 * Build the {@link Policy.PolicyRequest} a protected field asks. The principal
 * comes from context; the resource defaults to that same principal.
 */
const requestFor = <E>(
  options: ProtectedFieldOptions<E>,
): Effect.Effect<Policy.PolicyRequest, never, CurrentPrincipal> =>
  Effect.gen(function* () {
    const principal = yield* CurrentPrincipal;
    return Policy.request({
      principal,
      action: toActionRef(options.action),
      resource: options.resource ?? principal,
      ...(options.context !== undefined ? { context: options.context } : {}),
    });
  });

/**
 * Resolve the slice and run the pure kernel. `EntityResolver` is optional (an
 * empty slice still decides context-only and ownerless policies); a resolver
 * *failure* is fail-closed — it denies, matching the kernel's posture for
 * evaluation errors.
 */
const decide = <E>(
  policies: ReadonlyArray<Policy.Policy<E, never>>,
  request: Policy.PolicyRequest,
): Effect.Effect<boolean, never, never> =>
  Effect.gen(function* () {
    const resolver = yield* Effect.serviceOption(EntityResolver);
    const slice = yield* Option.isNone(resolver)
      ? Effect.succeed<Entity.EntitySlice | null>(Entity.emptySlice)
      : resolver.value.resolve(requestRefs(policies, request)).pipe(
          Effect.map((entities): Entity.EntitySlice | null => Entity.slice(entities)),
          Effect.catch(() => Effect.succeed<Entity.EntitySlice | null>(null)),
        );
    if (slice === null) return false;
    return yield* Policy.check(policies, request, slice);
  });

// ---------------------------------------------------------------------------
// The getter
// ---------------------------------------------------------------------------

/**
 * The guard both directions share: absent values pass through untouched (that
 * is `onSome`'s contract), a present value is authorized, and a denial either
 * omits the key or fails the parse.
 */
const guard = <A, E>(
  behavior: DenyBehavior,
  options: ProtectedFieldOptions<E>,
): SchemaGetter.Getter<A, A, CurrentPrincipal> => {
  const policies = toPolicies(options.policies);
  return SchemaGetter.onSome<A, A, CurrentPrincipal>((value) =>
    Effect.gen(function* () {
      const request = yield* requestFor(options);
      const allowed = yield* decide(policies, request);
      if (allowed) return Option.some(value);
      if (behavior === "redact") return Option.none<A>();
      return yield* Effect.fail(
        new SchemaIssue.Forbidden(Option.some(value), {
          message: `Authorization denied: ${Entity.formatRef(request.principal)} may not ${Entity.formatRef(request.action)} on ${Entity.formatRef(request.resource)}`,
        }),
      );
    }),
  );
};

// ---------------------------------------------------------------------------
// protectedField
// ---------------------------------------------------------------------------

/**
 * The type {@link protectedField} produces: the field's own schema, wrapped in
 * an authorization transformation that requires {@link CurrentPrincipal} on
 * both the decoding and the encoding side, and optional-keyed so redaction can
 * drop the key.
 *
 * `Schema.Struct` unions its fields' service requirements, so a struct holding
 * one protected field surfaces `CurrentPrincipal` in the `R` channel of
 * `Schema.decodeUnknownEffect` / `Schema.encodeEffect` — the compiler will not
 * let a caller run the codec without providing a principal.
 */
export interface ProtectedField<S extends Schema.Constraint> extends Schema.optionalKey<
  Schema.decodeTo<Schema.toType<S>, S, CurrentPrincipal, CurrentPrincipal>
> {}

/**
 * Protect a struct field with a policy.
 *
 * Decoding is the write-side guard and encoding is the viewer projection; see
 * the module docs for the defaults and why they differ. The returned schema is
 * optional-keyed: an absent value is always allowed, and a redacted value is
 * removed rather than set to `undefined`.
 *
 * @example Redact rather than reject on the write side
 * ```ts
 * Authz.protectedField(Schema.Boolean, {
 *   policies: Authz.Policy.role("admin"),
 *   action: "user:set-banned",
 *   onDecodeDeny: "redact",
 * })
 * ```
 */
export const protectedField = <S extends Schema.Top, E = unknown>(
  field: S,
  options: ProtectedFieldOptions<E>,
): ProtectedField<S> =>
  Schema.optionalKey(
    field.pipe(
      Schema.decode<S, CurrentPrincipal, CurrentPrincipal>({
        decode: guard<S["Type"], E>(options.onDecodeDeny ?? "fail", options),
        encode: guard<S["Type"], E>(options.onEncodeDeny ?? "redact", options),
      }),
    ),
  );
