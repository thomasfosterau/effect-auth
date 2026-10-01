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
 * parent `Record` lists the final segment AND the node at the full path is not
 * itself a `Record` (a `Record` there means other variables merely share the
 * prefix, e.g. `NAME_FILE=...`, so the secret is unset).
 *
 * The root `[[], name]` candidate only matters for map-style providers
 * (`fromUnknown({ NAME: "" })`); `fromEnv` is covered by the `_`-segmented one.
 *
 * Residual blind spot: `NAME=""` set together with `NAME_FILE=...` (or any
 * other `NAME_*` variable) reads as unset, because the provider then reports a
 * `Record` node at `NAME`.
 *
 * @module optional-secret-config
 * @internal
 */

import { Config, ConfigProvider, Option, Redacted, Schema } from "effect";

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
const recordKeys = (path: ConfigProvider.Path): Config.Config<ReadonlySet<string>> =>
  Config.flatMap(Config.succeed(undefined), () => {
    const seen = new Set<string>();
    const key = Schema.String.check(
      Schema.makeFilter((k: string) => {
        seen.add(k);
        return true;
      }),
    );
    return Config.schema(Schema.Record(key, Schema.UndefinedOr(Schema.String)), path).pipe(
      Config.map((): ReadonlySet<string> => seen),
      Config.withDefault(new Set<string>() as ReadonlySet<string>),
    );
  });

/**
 * True when `name` exists in the provider's source even though its value reads
 * as missing. Probes the flat key (map providers) and the `_`-segmented trie
 * that `fromEnv` builds.
 */
const isPresentButEmpty = (name: string): Config.Config<boolean> => {
  const segments = name.split("_");
  const candidates: ReadonlyArray<readonly [ConfigProvider.Path, string]> = [
    [[], name],
    [segments.slice(0, -1), segments[segments.length - 1]!],
  ];
  return Config.all(
    candidates.map(([parent, key]) =>
      Config.all([recordKeys(parent), recordKeys([...parent, key])]).pipe(
        Config.map(([siblings, below]) => siblings.has(key) && below.size === 0),
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
        return Redacted.value(value.value) === "" ? setButEmpty(name) : Config.succeed(value.value);
      }
      return isPresentButEmpty(name).pipe(
        Config.flatMap((empty): Config.Config<Redacted.Redacted | undefined> =>
          empty ? setButEmpty(name) : Config.succeed(undefined),
        ),
      );
    }),
  );
