import * as Auth from "effect-auth";
import { Effect } from "effect";
import { runAuth } from "./runtime.js";

export const hashPassword = (plaintext: string) =>
  runAuth(
    Effect.gen(function* () {
      const hasher = yield* Auth.PasswordHasher;
      const result = yield* hasher.hash(plaintext);
      return result.hash;
    }),
  );

export const verifyPassword = (plaintext: string, hash: string) =>
  runAuth(
    Effect.gen(function* () {
      const hasher = yield* Auth.PasswordHasher;
      return yield* hasher.verify(plaintext, hash);
    }),
  );
