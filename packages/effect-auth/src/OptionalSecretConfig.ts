/**
 * An optional secret `Config` that distinguishes UNSET from PRESENT-BUT-EMPTY.
 *
 * On Effect rc.118 the stock providers (`ConfigProvider.fromEnv`,
 * `fromUnknown`, ...) read `NAME=""` as absent, so `Config.option(...)` cannot
 * tell an operator who deliberately left an encryption secret unset (opt out)
 * from one whose templating or secrets manager rendered it as `""` (a mistake
 * that would otherwise silently disable encryption at rest).
 *
 * The raw distinction is still visible through the provider interface: a
 * provider reports a missing leaf as `undefined`, but its parent `Record`
 * node still lists the key. The probe is built from `Config.flatMap` and
 * `Config.schema`, so it is evaluated by the Config evaluator with the same
 * provider and path prefix as the rest of the config: it honours
 * `Config.nested(...)`, `.parse(provider)` and `ConfigProvider.layer`, and
 * never touches `process.env`.
 *
 * The probe relies on the documented `ConfigProvider.load` contract and the
 * `Node` shapes (`Record.keys`), observed through the key schema of
 * `Config.schema(Schema.Record(...))`. A name is "present but empty" when its
 * parent `Record` lists the final segment AND the node at the full path has no
 * children (a `Record` there, or an `Array` when the siblings are all numeric
 * suffixes such as `NAME_0` / `NAME_1`, means other variables merely share the
 * prefix, e.g. `NAME_FILE=...`, so the secret is unset).
 *
 * A value that is present but whitespace-only (`"   "`, a lone newline) counts
 * as empty (owner decision on #252); a secret with surrounding spaces but
 * non-space content is accepted unchanged and is not trimmed. No error message
 * ever contains a secret value.
 *
 * The root `[[], name]` candidate only matters for map-style providers
 * (`fromUnknown({ NAME: "" })`); `fromEnv` is covered by the `_`-segmented one.
 *
 * Residual blind spot: `NAME=""` set together with `NAME_FILE=...` (or any
 * other `NAME_*` variable) reads as unset, because the provider then reports a
 * `Record` or `Array` node at `NAME`. The owner accepted this on #252;
 * `ConfigEmptyEnv.test.ts` pins it so a future fix flips it deliberately.
 *
 * Further blind spots and misclassifications (documented, not fixed):
 *
 * - A composite `ConfigProvider.orElse` whose primary provider has a
 *   `NAME`-prefix sibling can hide an empty value in the fallback provider,
 *   because the probe sees the primary's `Record` / `Array` node first.
 * - Non-env `fromUnknown` shapes can be misclassified, because the
 *   `_`-segmented candidate is also probed there: a nested object at the
 *   segmented path (`{ A: { B: "" } }` for `A_B`) or an object at `NAME` itself
 *   is read as "prefix shared", i.e. unset.
 * - `fromUnknown({ NAME: ["a"] })` (an array value) is not a string: the
 *   `Array` node counts as "prefix shared", so it reads as unset (encryption
 *   off), not as "set but empty". Only string-valued secrets are supported.
 *
 * @module optional-secret-config
 * @internal
 */

import {
  Array as Arr,
  Config,
  ConfigProvider,
  Option,
  Redacted,
  Schema,
  String as Str,
} from "effect";

const setButEmpty = (name: string) =>
  Config.fail(
    new ConfigProvider.SourceError({
      message: `${name} is set but empty. Unset it to leave encryption off, or provide a non-empty secret.`,
    }),
  );

/**
 * The keys of the `Record` node at `path` (empty when the node is absent or
 * not a `Record`). The key set is collected per evaluation: the schema is built
 * inside `flatMap`, so concurrent evaluations never share state.
 */
const noKeys: ReadonlyArray<string> = [];

const recordKeys = (path: ConfigProvider.Path): Config.Config<ReadonlyArray<string>> =>
  Config.flatMap(Config.succeed(undefined), () => {
    const seen: Array<string> = [];
    const key = Schema.String.check(
      Schema.makeFilter((k: string) => {
        seen.push(k);
        return true;
      }),
    );
    return Config.schema(Schema.Record(key, Schema.UndefinedOr(Schema.String)), path).pipe(
      Config.map((): ReadonlyArray<string> => seen),
      Config.withDefault(noKeys),
    );
  });

/**
 * True when the node at `path` is an `Array` node. The `fromEnv` trie yields an
 * `Array` (not a `Record`) when every child segment is a canonical index, e.g.
 * `NAME_0` / `NAME_1`, so those siblings are invisible to `recordKeys`.
 */
const hasArrayChildren = (path: ConfigProvider.Path): Config.Config<boolean> =>
  Config.schema(Schema.Array(Schema.UndefinedOr(Schema.String)), path).pipe(
    Config.map(() => true),
    Config.withDefault(false),
  );

/**
 * True when `name` exists in the provider's source even though its value reads
 * as missing. Probes the flat key (map providers) and the `_`-segmented trie
 * that `fromEnv` builds.
 */
const isPresentButEmpty = (name: string): Config.Config<boolean> => {
  const segments = Str.split(name, "_");
  const candidates: ReadonlyArray<readonly [ConfigProvider.Path, string]> = [
    [[], name],
    [Arr.initNonEmpty(segments), Arr.lastNonEmpty(segments)],
  ];
  return Config.all(
    candidates.map(([parent, key]) =>
      Config.all([
        recordKeys(parent),
        recordKeys([...parent, key]),
        hasArrayChildren([...parent, key]),
      ]).pipe(
        Config.map(
          ([siblings, below, belowArray]) =>
            Arr.contains(siblings, key) && Arr.isReadonlyArrayEmpty(below) && !belowArray,
        ),
      ),
    ),
  ).pipe(Config.map((found) => found.some(Boolean)));
};

/**
 * `Config` for an opt-in secret: `undefined` when `name` is unset, the
 * redacted secret when it is non-empty, and a `ConfigError` naming `name` when
 * it is present but empty.
 */
export const optionalSecret = (name: string): Config.Config<Redacted.Redacted | undefined> =>
  Config.option(Config.Redacted(name)).pipe(
    Config.flatMap((value): Config.Config<Redacted.Redacted | undefined> => {
      if (Option.isSome(value)) {
        return Redacted.value(value.value).trim() === ""
          ? setButEmpty(name)
          : Config.succeed(value.value);
      }
      return isPresentButEmpty(name).pipe(
        Config.flatMap((empty): Config.Config<Redacted.Redacted | undefined> =>
          empty ? setButEmpty(name) : Config.succeed(undefined),
        ),
      );
    }),
  );
