import * as Auth from "effect-auth";
import { Effect } from "effect";
import { runAuth, sessionConfig } from "./runtime.js";

export const createSession = async (userId: string, attributes?: Record<string, unknown>) =>
  runAuth(
    Effect.gen(function* () {
      const manager = yield* Auth.makeSessionManager(sessionConfig);
      return yield* manager.createSession(userId, attributes);
    }),
  );

export const validateSession = async (sessionId: string) =>
  runAuth(
    Effect.gen(function* () {
      const manager = yield* Auth.makeSessionManager(sessionConfig);
      return yield* manager.validateSession(sessionId);
    }).pipe(Effect.result),
  );

export const invalidateSession = async (sessionId: string) =>
  runAuth(
    Effect.gen(function* () {
      const manager = yield* Auth.makeSessionManager(sessionConfig);
      yield* manager.invalidateSession(sessionId);
    }),
  );
