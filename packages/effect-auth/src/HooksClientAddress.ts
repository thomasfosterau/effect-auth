/**
 * Internal: records on a `Hooks` implementation which of its plugins key a limit
 * on the client address, so `Http.make` can check at build that the handler has
 * an address source (#389). No entry point exports this module, and the API
 * reference leaves it out (`docgen.json` excludes it).
 *
 * The record is a symbol-keyed property. A plugin built with `makePlugin` copies
 * its inner implementation with an object spread, which keeps symbol-keyed
 * properties, so the record survives the plugins stacked after it.
 *
 * @module HooksClientAddress
 * @internal
 */
import type { Hooks } from "./Hooks.ts";

const ClientAddressKeyed: unique symbol = Symbol.for(
  "@thomasfosterau/effect-auth/Hooks/clientAddressKeyed",
);

interface Recorded {
  readonly [ClientAddressKeyed]?: ReadonlyArray<string> | undefined;
}

/**
 * The plugins in this `Hooks` stack that key a limit on the client address.
 *
 * @internal
 */
export const clientAddressKeyedPlugins = (hooks: typeof Hooks.Service): ReadonlyArray<string> =>
  // SAFETY: `Recorded` only adds an optional symbol-keyed property that nothing
  // but `recordClientAddressKeyed` writes, always as a string array; any other
  // `Hooks` implementation lacks it and reads as `undefined`.
  (hooks as Recorded)[ClientAddressKeyed] ?? [];

/**
 * Record that `plugin` keys a limit on the client address.
 *
 * @internal
 */
export const recordClientAddressKeyed = (
  hooks: typeof Hooks.Service,
  plugin: string,
): typeof Hooks.Service => {
  const recorded: Recorded = {
    [ClientAddressKeyed]: [...clientAddressKeyedPlugins(hooks), plugin],
  };
  return { ...hooks, ...recorded };
};
