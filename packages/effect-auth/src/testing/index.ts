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
