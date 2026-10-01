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
 * node still lists the key. This module consults the active
 * `ConfigProvider` (no `process.env` access), so it works under any provider
 * the library supports.
 *
 * @module optional-secret-config
 * @internal
 */

import { Config, ConfigProvider, Effect, Option, Redacted } from "effect";

const configError = (message: string) =>
  new Config.ConfigError(new ConfigProvider.SourceError({ message }));

const setButEmpty = (name: string) =>
  configError(
    `${name} is set but empty. Unset it to leave encryption off, or provide a non-empty secret.`,
  );

/**
 * True when `name` exists in the provider's source even though its value reads
 * as missing. Probes both the flat key (`fromUnknown({ NAME: "" })`) and the
 * `_`-segmented trie `fromEnv` uses (`NAME` -> `NA` / `ME` ...).
 */
const keyIsPresent = (
  provider: ConfigProvider.ConfigProvider,
  name: string,
): Effect.Effect<boolean, Config.ConfigError> => {
  const segments = name.split("_");
  const candidates: ReadonlyArray<readonly [ConfigProvider.Path, string]> = [
    [[], name],
    [segments.slice(0, -1), segments[segments.length - 1]!],
  ];
  return Effect.forEach(candidates, ([parent, key]) =>
    provider.load(parent).pipe(
      Effect.map((node) => node !== undefined && node._tag === "Record" && node.keys.has(key)),
      Effect.mapError((cause) => new Config.ConfigError(cause)),
    ),
  ).pipe(Effect.map((found) => found.some(Boolean)));
};

/**
 * `Config` for an opt-in secret: `undefined` when `name` is unset, the
 * redacted secret when it is non-empty, and a `ConfigError` naming `name` when
 * it is present but empty.
 */
export const optionalSecret = (name: string): Config.Config<Redacted.Redacted | undefined> =>
  Config.succeed(undefined).pipe(
    Config.mapEffect(() =>
      Effect.gen(function* () {
        const provider = yield* ConfigProvider.ConfigProvider;
        const value = yield* Config.option(Config.Redacted(name)).parse(provider);
        if (Option.isSome(value)) {
          if (Redacted.value(value.value) === "") return yield* Effect.fail(setButEmpty(name));
          return value.value;
        }
        if (yield* keyIsPresent(provider, name)) return yield* Effect.fail(setButEmpty(name));
        return undefined;
      }),
    ),
  );
