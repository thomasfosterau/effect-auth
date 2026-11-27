/**
 * Confusables plugin: refuses a new email address that mixes scripts or passes
 * for an ASCII address, using UTS 39 (Unicode Security Mechanisms). Off unless
 * wired; it guards the `beforeClaimEmail` hook, which sign-up and email change
 * fire.
 *
 * The local part and each domain label (decoded from punycode) are judged
 * apart, so `山田@例え.jp` and `ivan@пример.рф` pass while `pаypal@example.com`
 * (a Cyrillic `а`) does not.
 *
 * @module plugins/confusables
 */
import * as Effect from "effect/Effect";
import * as Arr from "effect/Array";
import * as HashMap from "effect/HashMap";
import * as Option from "effect/Option";
import * as Result from "effect/Result";
import { ConfusableEmailError } from "../Errors.ts";
import * as Hooks from "../Hooks.ts";
import { CONFUSABLES, SCRIPTS, UNICODE_VERSION } from "./ConfusablesData.ts";
import { decodePunycode } from "./Punycode.ts";

/** The Unicode version of the confusables table {@link skeleton} maps with. */
export const CONFUSABLES_UNICODE_VERSION = UNICODE_VERSION;

// ---------------------------------------------------------------------------
// Skeleton (UTS 39 §4)
// ---------------------------------------------------------------------------

/** One table entry: a base-36 source delta and the target code points. */
const ENTRY = /^([0-9a-z]+):([0-9a-z.]+)$/;

let confusableTable: Option.Option<HashMap.HashMap<number, string>> = Option.none();

/** The table, decoded on first use. */
const confusables = (): HashMap.HashMap<number, string> => {
  if (Option.isSome(confusableTable)) return confusableTable.value;
  const entries = Arr.filterMap(CONFUSABLES.split(","), (entry) => {
    const match = ENTRY.exec(entry);
    return match === null
      ? Result.failVoid
      : Result.succeed([
          Number.parseInt(match[1] ?? "", 36),
          String.fromCodePoint(
            ...Arr.map((match[2] ?? "").split("."), (cp) => Number.parseInt(cp, 36)),
          ),
        ] as const);
  });
  // Each source is a delta from the previous one.
  const [, pairs] = Arr.mapAccum(entries, 0, (source, [delta, target]) => [
    source + delta,
    [source + delta, target] as const,
  ]);
  const table = HashMap.fromIterable(pairs);
  confusableTable = Option.some(table);
  return table;
};

/** The code points of `input`, one string each. */
const codePoints = (input: string): ReadonlyArray<string> => Arr.fromIterable(input);

const codePointOf = (char: string): number => char.codePointAt(0) ?? 0;

const ASCII = /^\p{ASCII}*$/u;

/**
 * The UTS 39 skeleton of `input`: NFD, each code point replaced by its
 * prototype from `confusables.txt`, NFD again. Two strings are confusable
 * when their skeletons are equal, so `skeleton("pаypal") === skeleton("paypal")`.
 * A skeleton is for comparison only; never show or store it as the value.
 *
 * @example
 * ```ts
 * import * as assert from "node:assert"
 * import { skeleton } from "@thomasfosterau/effect-auth/Plugins"
 *
 * assert.equal(skeleton("pаypal"), skeleton("paypal"))
 * assert.notEqual(skeleton("paypal"), skeleton("paypals"))
 * ```
 *
 * @since 0.9.0
 */
export const skeleton = (input: string): string => {
  const table = confusables();
  return Arr.map(codePoints(input.normalize("NFD")), (char) =>
    Option.getOrElse(HashMap.get(table, codePointOf(char)), () => char),
  )
    .join("")
    .normalize("NFD");
};

// ---------------------------------------------------------------------------
// Mixed-script detection (UTS 39 §5.1, §5.2)
// ---------------------------------------------------------------------------

/**
 * How far a string mixes scripts, from least to most: UTS 39 §5.2's
 * restriction levels without the identifier-status test.
 *
 * - `"ascii"`: only ASCII.
 * - `"single-script"`: one script (characters every script shares, such as
 *   digits and `.`, count for any; Han with Hiragana and Katakana, Han with
 *   Hangul and Han with Bopomofo count as one, as Japanese, Korean and
 *   Chinese text).
 * - `"highly-restrictive"`: Latin with one of those (Japanese, Korean or
 *   Chinese).
 * - `"moderately-restrictive"`: Latin with any one other script but
 *   Cyrillic, Greek and Cherokee, whose letters most resemble Latin.
 * - `"minimally-restrictive"`: anything else.
 *
 * @since 0.9.0
 */
export type RestrictionLevel =
  | "ascii"
  | "single-script"
  | "highly-restrictive"
  | "moderately-restrictive"
  | "minimally-restrictive";

const LEVELS: ReadonlyArray<RestrictionLevel> = [
  "ascii",
  "single-script",
  "highly-restrictive",
  "moderately-restrictive",
  "minimally-restrictive",
];

/** A script set; `None` is every script (a Common or Inherited character). */
type ScriptSet = Option.Option<ReadonlyArray<string>>;

const COMMON_OR_INHERITED = /^[\p{scx=Zyyy}\p{scx=Zinh}]$/u;

/** `\p{scx=…}` throws for a script newer than the runtime's Unicode. */
const scriptTest = Option.liftThrowable((code: string) => new RegExp(`^\\p{scx=${code}}$`, "u"));

let scriptTests: Option.Option<ReadonlyArray<readonly [string, RegExp]>> = Option.none();

/** One test per script the runtime's Unicode knows; newer scripts are skipped. */
const scriptRegExps = (): ReadonlyArray<readonly [string, RegExp]> => {
  if (Option.isSome(scriptTests)) return scriptTests.value;
  const tests = Arr.filterMap(SCRIPTS, (code) =>
    Option.match(scriptTest(code), {
      onNone: () => Result.failVoid,
      onSome: (test) => Result.succeed([code, test] as const),
    }),
  );
  scriptTests = Option.some(tests);
  return tests;
};

/** UTS 39 §5.1's augmentation: Han, kana and Hangul also count as the writing systems that use them. */
const AUGMENT = HashMap.make<ReadonlyArray<readonly [string, ReadonlyArray<string>]>>(
  ["Hani", ["Hanb", "Jpan", "Kore"]],
  ["Hira", ["Jpan"]],
  ["Kana", ["Jpan"]],
  ["Hang", ["Kore"]],
  ["Bopo", ["Hanb"]],
);

const augmentOf = (code: string): ReadonlyArray<string> =>
  Option.getOrElse(HashMap.get(AUGMENT, code), () => []);

/**
 * The augmented Script_Extensions of one character. A character the runtime
 * assigns no script gets `Zzzz` (Unknown), which shares no script with
 * anything else.
 */
const scriptsOf = (char: string): ScriptSet => {
  if (/^[A-Za-z]$/.test(char)) return Option.some(["Latn"]);
  if (codePointOf(char) < 0x80 || COMMON_OR_INHERITED.test(char)) return Option.none();
  const found = Arr.flatMap(scriptRegExps(), ([code, test]) =>
    test.test(char) ? [code, ...augmentOf(code)] : [],
  );
  return Option.some(Arr.isArrayNonEmpty(found) ? Arr.dedupe(found) : ["Zzzz"]);
};

/** The identity of {@link intersect}. */
const everyScript = (): ScriptSet => Option.none();

const intersect = (a: ScriptSet, b: ScriptSet): ScriptSet =>
  Option.isNone(a) ? b : Option.isNone(b) ? a : Option.some(Arr.intersection(a.value, b.value));

/** The resolved script set of `input` (UTS 39 §5.1), skipping characters in `ignore`. */
const resolvedScripts = (input: string, ignore?: string): ScriptSet =>
  Arr.reduce(
    codePoints(input.normalize("NFD")),
    everyScript(),
    (resolved: ScriptSet, char): ScriptSet => {
      const scripts = scriptsOf(char);
      return ignore !== undefined && Option.isSome(scripts) && Arr.contains(scripts.value, ignore)
        ? resolved
        : intersect(resolved, scripts);
    },
  );

const isEmpty = (set: ScriptSet): boolean =>
  Option.isSome(set) && !Arr.isReadonlyArrayNonEmpty(set.value);

/**
 * The UTS 39 §5.2 restriction level of `input`; see {@link RestrictionLevel}.
 *
 * @example
 * ```ts
 * import * as assert from "node:assert"
 * import { restrictionLevel } from "@thomasfosterau/effect-auth/Plugins"
 *
 * assert.equal(restrictionLevel("paypal"), "ascii")
 * assert.equal(restrictionLevel("пример"), "single-script")
 * assert.equal(restrictionLevel("abc山田"), "highly-restrictive")
 * assert.equal(restrictionLevel("pаypal"), "minimally-restrictive")
 * ```
 *
 * @since 0.9.0
 */
export const restrictionLevel = (input: string): RestrictionLevel => {
  if (ASCII.test(input)) return "ascii";
  if (!isEmpty(resolvedScripts(input))) return "single-script";
  const resolvedWithoutLatin = resolvedScripts(input, "Latn");
  if (Option.isNone(resolvedWithoutLatin)) return "single-script";
  const withoutLatin = resolvedWithoutLatin.value;
  const has = (code: string) => Arr.contains(withoutLatin, code);
  if (has("Zzzz")) return "minimally-restrictive";
  if (Arr.some(["Jpan", "Kore", "Hanb"], has)) return "highly-restrictive";
  if (Arr.isReadonlyArrayNonEmpty(withoutLatin) && !Arr.some(["Cyrl", "Grek", "Cher"], has)) {
    return "moderately-restrictive";
  }
  return "minimally-restrictive";
};

/** A domain label as Unicode: an `xn--` label decoded, a malformed one as written. */
const unicodeLabel = (label: string): string =>
  /^xn--/i.test(label) ? Option.getOrElse(decodePunycode(label.slice(4)), () => label) : label;

// ---------------------------------------------------------------------------
// Email check
// ---------------------------------------------------------------------------

/** The parts of an address the checks judge apart: the local part and each domain label. */
const addressParts = (email: string): ReadonlyArray<string> => {
  const at = email.lastIndexOf("@");
  if (at < 0) return [email];
  return [
    email.slice(0, at),
    ...email
      .slice(at + 1)
      .split(".")
      .map(unicodeLabel),
  ];
};

/** The scripts a part may mix, or `false` for no mixed-script check. */
export type ConfusablesRestriction =
  | "single-script"
  | "highly-restrictive"
  | "moderately-restrictive"
  | false;

/** Configuration for {@link ConfusablesPlugin}. */
export interface ConfusablesConfig {
  /**
   * The most each part (the local part, each domain label) may mix scripts;
   * see {@link RestrictionLevel}. `false` turns the check off. Default
   * `"highly-restrictive"`: one script, or Latin with Japanese, Korean or
   * Chinese.
   */
  readonly restriction?: ConfusablesRestriction;
  /**
   * Refuse a part that is not ASCII but whose {@link skeleton} is, so it can
   * pass for an ASCII name (`раураl`, all Cyrillic, for `paypal`; full-width
   * `ｐａｙｐａｌ`). Default `true`.
   */
  readonly asciiLookalikes?: boolean;
  /** The flows to guard. Default both, `["sign-up", "email-change"]`. */
  readonly flows?: ReadonlyArray<Hooks.ClaimEmailFlow>;
}

/**
 * Why {@link ConfusablesPlugin} with `config` would refuse `email`, or none.
 * `email` is normalized first (`normalizeEmail` leaves it unchanged when it
 * already is).
 *
 * @example
 * ```ts
 * import * as assert from "node:assert"
 * import * as Option from "effect/Option"
 * import { confusableEmailReason } from "@thomasfosterau/effect-auth/Plugins"
 *
 * assert.deepEqual(confusableEmailReason("pаypal@example.com"), Option.some("mixed-script"))
 * assert.deepEqual(confusableEmailReason("раураl@example.com"), Option.some("mixed-script"))
 * assert.deepEqual(confusableEmailReason("рау@example.com"), Option.some("ascii-lookalike"))
 * assert.deepEqual(confusableEmailReason("ivan@xn--e1afmkfd.xn--p1ai"), Option.none())
 * ```
 *
 * @since 0.9.0
 */
export const confusableEmailReason = (
  email: string,
  config: ConfusablesConfig = {},
): Option.Option<ConfusableEmailError["reason"]> => {
  const restriction = config.restriction ?? "highly-restrictive";
  const asciiLookalikes = config.asciiLookalikes ?? true;
  const parts = addressParts(email.trim());
  if (
    restriction !== false &&
    Arr.some(parts, (part) => LEVELS.indexOf(restrictionLevel(part)) > LEVELS.indexOf(restriction))
  ) {
    return Option.some("mixed-script");
  }
  if (
    asciiLookalikes &&
    Arr.some(parts, (part) => !ASCII.test(part) && ASCII.test(skeleton(part)))
  ) {
    return Option.some("ascii-lookalike");
  }
  return Option.none();
};

/**
 * Build the confusables plugin: `beforeClaimEmail` fails with
 * {@link ConfusableEmailError} for an address {@link confusableEmailReason}
 * refuses, in the flows `config.flows` names. Addresses already held are
 * never judged; only a new address a user chooses is.
 *
 * `Layer<Hooks, never, Hooks>`: no dependencies.
 *
 * @example
 * ```ts
 * import * as assert from "node:assert"
 * import { Effect, Exit, Layer } from "effect"
 * import { Hooks } from "@thomasfosterau/effect-auth/Hooks"
 * import { ConfusablesPlugin } from "@thomasfosterau/effect-auth/Plugins"
 *
 * const claim = (email: string) =>
 *   Effect.gen(function* () {
 *     const hooks = yield* Hooks
 *     return yield* hooks.beforeClaimEmail({ email, flow: "sign-up" })
 *   }).pipe(Effect.provide(ConfusablesPlugin().pipe(Layer.provide(Hooks.Default))))
 *
 * assert.ok(Exit.isSuccess(Effect.runSyncExit(claim("paypal@example.com"))))
 * assert.ok(Exit.isFailure(Effect.runSyncExit(claim("pаypal@example.com"))))
 * ```
 *
 * @since 0.9.0
 */
export const ConfusablesPlugin = (config: ConfusablesConfig = {}) => {
  const flows = config.flows ?? ["sign-up", "email-change"];
  return Hooks.makePlugin({
    beforeClaimEmail: (args: Hooks.ClaimEmailArgs) => {
      if (!Arr.contains(flows, args.flow)) return Effect.succeed(args);
      return Option.match(confusableEmailReason(args.email, config), {
        onNone: () => Effect.succeed(args),
        onSome: (reason) =>
          Effect.fail(
            new ConfusableEmailError({
              message: "This email address can be mistaken for another; please use a different one",
              reason,
            }),
          ),
      });
    },
  });
};
