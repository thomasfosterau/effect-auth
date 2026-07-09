/**
 * Re-export barrel for the session module.
 *
 * The session module was split into SessionService / SessionStore / UserStore.
 * This file re-exports everything under the original names so that consumers
 * can update their imports incrementally.
 */
export {
  SessionService as SessionManager,
  make as makeSessionManager,
  type SessionService as SessionManagerShape,
} from "./SessionService.ts";
export { SessionStore, type SessionStore as SessionStoreShape } from "./SessionStore.ts";
export { UserStore, type UserStore as UserStoreShape } from "./UserStore.ts";
