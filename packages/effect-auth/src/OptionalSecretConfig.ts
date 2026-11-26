/**
 * An optional secret `Config` that tells an unset name from one set to an empty
 * or whitespace-only value, which the stock providers both read as absent. It
 * probes the provider's `Record` node for the key; the known blind spots are
 * pinned in `ConfigEmptyEnv.test.ts`.
 *
 * @module optional-secret-config
 * @internal
 */

import { Config, ConfigProvider, Redacted } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as Str from "effect/String";

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
