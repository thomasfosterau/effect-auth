/**
 * Guard-negative helpers: assert, in one line, that an operation refuses an
 * anonymous viewer, refuses a viewer one rung too low, and admits the rung it
 * names and the owner, with the status mapping `Guard` documents:
 *
 * | Case                      | write             | read                 |
 * | ------------------------- | ----------------- | -------------------- |
 * | anonymous                 | `Unauthorized` (401) | the app's not-found (404) |
 * | one rung below the minimum | `Forbidden` (403) | the app's not-found (404) |
 * | at the minimum            | allowed           | allowed              |
 * | the owner (below the minimum) | allowed       | allowed              |
 *
 * A read the viewer may not see must look exactly like a missing row, so a
 * read's refusals expect the app's not-found error (matched by `_tag`,
 * `"NotFound"` by default), never `Forbidden`.
 *
 * Each helper is an `Effect` that fails with {@link GuardExpectationError}
 * listing every case that came out wrong, so it runs under any test runner.
 *
 * @module testing
 */
import { type Context, Data, Effect, Exit, Option } from "effect";
import * as Ladder from "../Ladder.ts";
import type * as SessionContext from "../SessionContext.ts";
import { runAsViewer, type ViewerFixture } from "./RunAs.ts";

/**
 * One case whose outcome was not the expected one.
 *
 * @since 1.0.0
 * @category models
 */
export interface GuardMismatch {
  /** Which viewer ran: `"anonymous"`, `"below <rung>"`, `"at <rung>"`, `"owner"`. */
  readonly case: string;
  /** `"allowed"`, or the `_tag` of the expected failure. */
  readonly expected: string;
  /** `"allowed"`, the `_tag` of the failure, `"failure"` for an untagged one, or `"defect"`. */
  readonly actual: string;
}

/**
 * An operation's guard did not behave as expected.
 *
 * @since 1.0.0
 * @category errors
 */
export class GuardExpectationError extends Data.TaggedError("GuardExpectationError")<{
  readonly message: string;
  readonly mismatches: ReadonlyArray<GuardMismatch>;
}> {}

/**
 * Whether the operation is a write (refusals are 401 / 403) or a read
 * (refusals are 404).
 *
 * @since 1.0.0
 * @category models
 */
export type Access = "write" | "read";

/**
 * Which errors count as each refusal.
 *
 * @since 1.0.0
 * @category models
 */
export interface RefusalOptions {
  /** Defaults to `"write"`. */
  readonly access?: Access | undefined;
  /** The `_tag` of the app's not-found error, expected for a read. Defaults to `"NotFound"`. */
  readonly notFoundTag?: string | undefined;
}

const outcomeOf = <A, E>(exit: Exit.Exit<A, E>): string => {
  if (Exit.isSuccess(exit)) return "allowed";
  const error = Exit.findErrorOption(exit);
  if (Option.isNone(error)) return "defect";
  const value: unknown = error.value;
  return typeof value === "object" &&
    value !== null &&
    "_tag" in value &&
    typeof value._tag === "string"
    ? value._tag
    : "failure";
};

const refusal = (options: RefusalOptions | undefined, write: string): string =>
  (options?.access ?? "write") === "read" ? (options?.notFoundTag ?? "NotFound") : write;

interface Case<User> {
  readonly name: string;
  readonly user: User | null;
  readonly expected: string;
}

const check = <Id, User extends ViewerFixture, A, E, R>(
  operation: Effect.Effect<A, E, R>,
  viewer: Context.Key<Id, Option.Option<User>>,
  cases: ReadonlyArray<Case<User>>,
): Effect.Effect<
  void,
  GuardExpectationError,
  Exclude<R, Id | SessionContext.MaybeCurrentSession>
> =>
  Effect.forEach(cases, (expectation) =>
    Effect.map(
      Effect.exit(operation.pipe(runAsViewer(viewer, expectation.user))),
      (exit): GuardMismatch | undefined => {
        const actual = outcomeOf(exit);
        return actual === expectation.expected
          ? undefined
          : { case: expectation.name, expected: expectation.expected, actual };
      },
    ),
  ).pipe(
    Effect.flatMap((results) => {
      const mismatches = results.filter((result) => result !== undefined);
      return mismatches.length === 0
        ? Effect.void
        : Effect.fail(
            new GuardExpectationError({
              message: `guard expectations failed: ${mismatches
                .map((m) => `${m.case}: expected ${m.expected}, got ${m.actual}`)
                .join("; ")}`,
              mismatches,
            }),
          );
    }),
  );

/**
 * Assert that `operation` refuses an anonymous viewer: `Unauthorized` for a
 * write, the app's not-found for a read.
 *
 * @since 1.0.0
 * @category assertions
 */
export const expectRefusesAnonymous = <Id, User extends ViewerFixture, A, E, R>(
  operation: Effect.Effect<A, E, R>,
  viewer: Context.Key<Id, Option.Option<User>>,
  options?: RefusalOptions,
): Effect.Effect<
  void,
  GuardExpectationError,
  Exclude<R, Id | SessionContext.MaybeCurrentSession>
> =>
  check(operation, viewer, [
    { name: "anonymous", user: null, expected: refusal(options, "Unauthorized") },
  ]);

/**
 * What {@link expectRefusesBelow} and {@link expectGuarded} need to know about
 * the gate.
 *
 * @since 1.0.0
 * @category models
 */
export interface RungOptions<User, Rung extends string> extends RefusalOptions {
  readonly ladder: Ladder.Ladder<Rung>;
  /** The rung or axis the operation's gate names. */
  readonly min: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>;
  /** The app's viewer holding `rung`. */
  readonly viewerAt: (rung: Rung) => User;
}

const below = <Rung extends string>(
  ladder: Ladder.Ladder<Rung>,
  min: Rung | Ladder.Axis<Rung>,
): Rung | undefined => ladder.rungs[ladder.rank(Ladder.minOf(min)) - 1];

/**
 * Assert that `operation` refuses a viewer one rung below `min` (`Forbidden`
 * for a write, the app's not-found for a read) and admits a viewer at `min`.
 *
 * When `min` is the lowest rung there is no rung below it; only the
 * admission is checked.
 *
 * @since 1.0.0
 * @category assertions
 */
export const expectRefusesBelow = <Id, User extends ViewerFixture, Rung extends string, A, E, R>(
  operation: Effect.Effect<A, E, R>,
  viewer: Context.Key<Id, Option.Option<User>>,
  options: RungOptions<User, Rung>,
): Effect.Effect<
  void,
  GuardExpectationError,
  Exclude<R, Id | SessionContext.MaybeCurrentSession>
> => check(operation, viewer, rungCases(options));

const rungCases = <User, Rung extends string>(
  options: RungOptions<User, Rung>,
): ReadonlyArray<Case<User>> => {
  const min = Ladder.minOf(options.min);
  const lower = below(options.ladder, options.min);
  return [
    ...(lower === undefined
      ? []
      : [
          {
            name: `below ${lower}`,
            user: options.viewerAt(lower),
            expected: refusal(options, "Forbidden"),
          },
        ]),
    { name: `at ${min}`, user: options.viewerAt(min), expected: "allowed" },
  ];
};

/**
 * Assert that `operation` admits `owner`. Give the owner a rung below the
 * gate's minimum, so the admission is the ownership's and not the rung's.
 *
 * @since 1.0.0
 * @category assertions
 */
export const expectAllowsOwner = <Id, User extends ViewerFixture, A, E, R>(
  operation: Effect.Effect<A, E, R>,
  viewer: Context.Key<Id, Option.Option<User>>,
  owner: NoInfer<User>,
): Effect.Effect<
  void,
  GuardExpectationError,
  Exclude<R, Id | SessionContext.MaybeCurrentSession>
> => check(operation, viewer, [{ name: "owner", user: owner, expected: "allowed" }]);

/**
 * Options for {@link expectGuarded}.
 *
 * @since 1.0.0
 * @category models
 */
export interface GuardedOptions<User, Rung extends string> extends RungOptions<User, Rung> {
  /**
   * The resource's owner, held below `min`. Given, the owner must be admitted
   * (an owner-or-rung gate); omitted, ownership is not checked.
   */
  readonly owner?: User | undefined;
}

/**
 * Every guard-negative case in one line: anonymous is refused, one rung below
 * `min` is refused, `min` is admitted, and (when given) the owner is admitted.
 * Refusals are `Unauthorized` / `Forbidden` for a write and the app's
 * not-found for a read.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Context, Effect, Option } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 * import * as Testing from "@thomasfosterau/effect-auth/testing"
 *
 * interface AppUser { readonly id: string; readonly role: string }
 * class CurrentViewer extends Context.Service<CurrentViewer, Option.Option<AppUser>>()(
 *   "@app/CurrentViewer",
 * ) {}
 *
 * const Roles = Auth.Ladder.make(["user", "contributor", "moderator"])
 * const guards = Auth.Guard.make({ ladder: Roles, viewer: CurrentViewer })
 *
 * const author: AppUser = { id: "u-author", role: "user" }
 * const editPost = guards.requireOwnerOrRole(author.id, "moderator")
 *
 * await Effect.runPromise(
 *   Testing.expectGuarded(editPost, CurrentViewer, {
 *     ladder: Roles,
 *     min: "moderator",
 *     viewerAt: (role) => ({ id: `u-${role}`, role }),
 *     owner: author,
 *   }),
 * )
 *
 * // An operation that forgot its gate fails the expectation.
 * const unguarded = Effect.succeed("edited")
 * const result = await Effect.runPromise(
 *   Effect.result(
 *     Testing.expectGuarded(unguarded, CurrentViewer, {
 *       ladder: Roles,
 *       min: "moderator",
 *       viewerAt: (role) => ({ id: `u-${role}`, role }),
 *     }),
 *   ),
 * )
 * assert.equal(result._tag, "Failure")
 * ```
 *
 * @since 1.0.0
 * @category assertions
 */
export const expectGuarded = <Id, User extends ViewerFixture, Rung extends string, A, E, R>(
  operation: Effect.Effect<A, E, R>,
  viewer: Context.Key<Id, Option.Option<User>>,
  options: GuardedOptions<User, Rung>,
): Effect.Effect<
  void,
  GuardExpectationError,
  Exclude<R, Id | SessionContext.MaybeCurrentSession>
> =>
  check(operation, viewer, [
    { name: "anonymous", user: null, expected: refusal(options, "Unauthorized") },
    ...rungCases(options),
    ...(options.owner === undefined
      ? []
      : [{ name: "owner", user: options.owner, expected: "allowed" }]),
  ]);
