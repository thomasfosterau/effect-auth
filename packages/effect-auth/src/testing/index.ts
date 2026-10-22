/**
 * `@thomasfosterau/effect-auth/testing`: server-side test helpers for
 * applications built on effect-auth. Not reachable from the package root, and
 * free of the HTTP tier.
 *
 * @since 1.0.0
 */
export {
  type AuthenticatedServices,
  type RunAsOptions,
  type ViewerFixture,
  type ViewerOptions,
  layerAs,
  runAs,
  runAsViewer,
  sessionFor,
  viewerLayerAs,
} from "./RunAs.ts";
export {
  type FixtureUserOptions,
  type FixtureUsers,
  type FixtureUsersOptions,
  fixtureEpoch,
  fixtureUser,
  fixtureUserIds,
  fixtureUsers,
} from "./Users.ts";
export {
  type Access,
  type GuardedOptions,
  GuardExpectationError,
  type GuardMismatch,
  type RefusalOptions,
  type RungOptions,
  expectAllowsOwner,
  expectGuarded,
  expectRefusesAnonymous,
  expectRefusesBelow,
} from "./GuardExpectations.ts";
