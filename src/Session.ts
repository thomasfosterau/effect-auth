/**
 * Compatibility re-export.
 *
 * `Session.ts` was split into `SessionService.ts`, `SessionStore.ts`, and
 * `UserStore.ts`. This shim lets existing imports continue to resolve while
 * the codebase migrates to the new paths.
 *
 * @module session
 */
export { SessionService as SessionManager, make as makeSessionManager } from "./SessionService.ts";
export type { SessionServiceShape as SessionManagerShape } from "./SessionService.ts";
export { SessionStore } from "./SessionStore.ts";
export { UserStore } from "./UserStore.ts";
