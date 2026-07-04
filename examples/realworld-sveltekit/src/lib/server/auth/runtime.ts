import * as Auth from "effect-auth";
import { Context, Effect } from "effect";
import { sessionStore, userStore } from "./adapters.js";

export const sessionConfig: Auth.SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24 * 30,
    idlePeriod: 1000 * 60 * 60 * 24 * 14,
  },
};

export type AppServices = Auth.SessionStore | Auth.UserStore | Auth.PasswordHasher;

const AppContext: Context.Context<AppServices> = Context.merge(
  Context.merge(
    Context.make(Auth.SessionStore, sessionStore),
    Context.make(Auth.UserStore, userStore),
  ),
  Context.make(Auth.PasswordHasher, Auth.makePBKDF2Hasher()),
);

const globalForAuth = globalThis as unknown as {
  __conduitAuthContext?: Context.Context<AppServices>;
};
const sharedContext = globalForAuth.__conduitAuthContext ?? AppContext;
if (process.env.NODE_ENV !== "production") globalForAuth.__conduitAuthContext = sharedContext;

export const runAuth = <A, E>(eff: Effect.Effect<A, E, AppServices | Auth.Hooks>) =>
  // No-op hooks base; swap for `composePlugins([...]).pipe(Layer.provide(Auth.Hooks.Default))`.
  Effect.runPromise(Effect.provide(eff, sharedContext).pipe(Effect.provide(Auth.Hooks.Default)));

export { Auth };
