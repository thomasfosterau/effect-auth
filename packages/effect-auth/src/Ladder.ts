import * as Option from "effect/Option";

/**
 * An ordered role ladder, least to most privileged: a rank function, the one
 * "at least this rung" comparison and named capability axes. An unknown rung
 * and anonymous satisfy nothing. The module imports only `effect/Option`, so a
 * browser loads `./ladder` without the rest of the Effect runtime. The example
 * is on {@link make}.
 *
 * @since 0.1.0
 * @category models
 */
export interface Ladder<Rung extends string> {
  /** The rungs, least → most privileged. */
  readonly rungs: ReadonlyArray<Rung>;
  /** Position of `role` on the ladder, least → most privileged; `-1` when it is not a rung. */
  readonly rank: (role: string) => number;
  /** Whether `role` is a rung of this ladder. */
  readonly isRung: (role: unknown) => role is Rung;
  /**
   * Whether `holder` holds `min` (a rung or an axis) or a more privileged rung.
   * Fails closed on anonymous (`None`) and on a role string that is not on the
   * ladder.
   */
  readonly hasAtLeast: (
    holder: Option.Option<RungHolder>,
    min: NoInfer<Rung> | Axis<NoInfer<Rung>>,
  ) => boolean;
  /** The rungs that satisfy `min`: `min` itself and every rung above it. */
  readonly atOrAbove: (min: NoInfer<Rung> | Axis<NoInfer<Rung>>) => ReadonlyArray<Rung>;
  /** Declare one named capability axis. */
  readonly axis: (name: string, min: NoInfer<Rung>) => Axis<Rung>;
  /**
   * Declare every capability axis at once, keyed by name. The returned record
   * is what call sites import: `requireRoleAtLeast(Axes.corpusWrite)`.
   */
  readonly axes: <const Declared extends Readonly<Record<string, NoInfer<Rung>>>>(
    declared: Declared,
  ) => { readonly [K in keyof Declared]: Axis<Rung> };
}

/**
 * Anything that holds a rung. Structural on purpose: a server-side user record,
 * a client-side session user and a test fixture all satisfy it, so the server
 * guard and the browser UX gate share one comparison.
 *
 * @since 0.1.0
 * @category models
 */
export interface RungHolder {
  readonly role: string;
}

/**
 * A named capability axis: "this capability needs at least `min`". Built by
 * {@link Ladder.axis} / {@link Ladder.axes}; accepted wherever a rung is.
 *
 * @since 0.1.0
 * @category models
 */
export interface Axis<Rung extends string = string> {
  readonly _tag: "LadderAxis";
  /** The axis name, for traces, policy ids and error messages. */
  readonly name: string;
  /** The lowest rung that satisfies the axis. */
  readonly min: Rung;
}

/**
 * The rung union of a ladder: `RungOf<typeof Roles>`.
 *
 * @since 0.1.0
 * @category models
 */
export type RungOf<L> = L extends Ladder<infer Rung> ? Rung : never;

/**
 * Whether a value is an {@link Axis}.
 *
 * @since 0.1.0
 * @category guards
 */
export const isAxis = (value: unknown): value is Axis =>
  typeof value === "object" && value !== null && "_tag" in value && value._tag === "LadderAxis";

/**
 * The lowest rung a rung-or-axis names.
 *
 * @since 0.1.0
 * @category getters
 */
export const minOf = <Rung extends string>(min: Rung | Axis<Rung>): Rung =>
  typeof min === "string" ? min : min.min;

/**
 * Declare a ladder from its rungs, least → most privileged.
 *
 * Throws on an empty ladder or a duplicate rung. Those are configuration
 * errors in module-level code, not runtime conditions, and a ladder with two
 * positions for one rung would make `rank` ambiguous — a silent mis-grant.
 * An axis naming a rung that is not on the ladder throws for the same reason.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import * as Option from "effect/Option"
 * import * as Ladder from "@thomasfosterau/effect-auth/ladder"
 *
 * export const Roles = Ladder.make(["user", "contributor", "moderator", "admin"])
 * export type Role = Ladder.RungOf<typeof Roles>
 *
 * export const Axes = Roles.axes({
 *   corpusWrite: "contributor",
 *   moderate: "moderator",
 *   viewPrivate: "moderator",
 *   viewDeleted: "moderator",
 * })
 *
 * assert.equal(Roles.hasAtLeast(Option.some({ role: "moderator" }), Axes.corpusWrite), true)
 * assert.equal(Roles.hasAtLeast(Option.some({ role: "superadmin" }), "user"), false) // off the ladder
 * assert.equal(Roles.hasAtLeast(Option.none(), "user"), false) // anonymous
 * ```
 *
 * @since 0.1.0
 * @category constructors
 */
export const make = <const Rungs extends readonly [string, ...Array<string>]>(
  rungs: Rungs,
): Ladder<Rungs[number]> => {
  type Rung = Rungs[number];
  if (rungs.length === 0) throw new Error("Ladder.make: a ladder needs at least one rung");
  const positions = new Map<string, number>();
  rungs.forEach((rung, index) => {
    if (positions.has(rung)) throw new Error(`Ladder.make: duplicate rung "${rung}"`);
    positions.set(rung, index);
  });
  const frozen: ReadonlyArray<Rung> = Object.freeze([...rungs]);

  const rank = (role: string): number => positions.get(role) ?? -1;
  const isKnownRung = (role: string): role is Rung => positions.has(role);
  const isRung = (role: unknown): role is Rung => typeof role === "string" && isKnownRung(role);

  const requireRung = (rung: string, context: string): Rung => {
    if (!isKnownRung(rung))
      throw new Error(`Ladder: ${context} names "${rung}", which is not a rung`);
    return rung;
  };

  const hasAtLeast = (holder: Option.Option<RungHolder>, min: Rung | Axis<Rung>): boolean => {
    if (Option.isNone(holder)) return false;
    const held = rank(holder.value.role);
    // `held >= 0` is what makes an off-ladder role fail closed even against
    // an off-ladder `min` (which `axis` refuses to build, but a cast could).
    return held >= 0 && held >= rank(minOf(min));
  };

  const atOrAbove = (min: Rung | Axis<Rung>): ReadonlyArray<Rung> => {
    const from = rank(minOf(min));
    return from < 0 ? [] : frozen.slice(from);
  };

  const axis = (name: string, min: Rung): Axis<Rung> =>
    Object.freeze({ _tag: "LadderAxis", name, min: requireRung(min, `axis "${name}"`) });

  const axes = <const Declared extends Readonly<Record<string, Rung>>>(
    declared: Declared,
  ): { readonly [K in keyof Declared]: Axis<Rung> } =>
    // SAFETY: the entries map one-to-one over `declared`'s own keys, each to an
    // `Axis<Rung>`, so the result has exactly the keys of `Declared`.
    Object.freeze(
      Object.fromEntries(Object.entries(declared).map(([name, min]) => [name, axis(name, min)])),
    ) as { readonly [K in keyof Declared]: Axis<Rung> };

  return Object.freeze({ rungs: frozen, rank, isRung, hasAtLeast, atOrAbove, axis, axes });
};
