import { assert, describe, expect, it } from "vite-plus/test";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Result from "effect/Result";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import { ApiKeyService } from "./ApiKey.ts";
import * as Impersonation from "./Impersonation.ts";
import { CurrentSession, MaybeCurrentSession } from "./SessionContext.ts";
import * as SessionContext from "./SessionContext.ts";
import { apiKeyServiceLayer, fixtureUser } from "./testing/index.ts";
import type * as Types from "./Types.ts";

const user: Types.User = { ...fixtureUser(), id: "user-1" };

const now = DateTime.nowUnsafe();
const later = DateTime.add(now, { minutes: 1 });

const sessionWith = (attributes: Types.Attributes): Types.Session => ({
  id: "digest",
  userId: user.id,
  expiresAt: DateTime.toDateUtc(later),
  createdAt: DateTime.toDateUtc(now),
  lastActivityAt: DateTime.toDateUtc(now),
  attributes,
});

const plain = sessionWith({});
const impersonation = sessionWith({
  impersonatedBy: "admin-1",
  impersonationExpiresAt: DateTime.toEpochMillis(later),
});

const outcome = <A, E>(effect: Effect.Effect<A, E>) => Effect.runPromise(Effect.result(effect));

describe("Impersonation.guardCurrentSession", () => {
  it("passes with no session in context", async () => {
    expect(Result.isSuccess(await outcome(Impersonation.guardCurrentSession))).toBe(true);
    const anonymous = Impersonation.guardCurrentSession.pipe(
      Effect.provide(SessionContext.anonymousLayer),
    );
    expect(Result.isSuccess(await outcome(anonymous))).toBe(true);
  });

  it("refuses an impersonation in CurrentSession or MaybeCurrentSession", async () => {
    const cases = [
      Impersonation.guardCurrentSession.pipe(
        Effect.provide(Layer.succeed(CurrentSession, impersonation)),
      ),
      Impersonation.guardCurrentSession.pipe(
        Effect.provide(
          Layer.succeed(MaybeCurrentSession, Option.some({ session: impersonation, user })),
        ),
      ),
    ];
    const results = await Promise.all(cases.map(outcome));
    Arr.forEach(results, (result) => {
      assert(Result.isFailure(result));
      expect(result.failure._tag).toBe("ImpersonationForbiddenError");
      expect(result.failure.code).toBe("IMPERSONATION_FORBIDDEN");
    });
    const allowed = Impersonation.guardCurrentSession.pipe(
      Effect.provide(Layer.succeed(CurrentSession, plain)),
    );
    expect(Result.isSuccess(await outcome(allowed))).toBe(true);
  });
});

const runApiKeyWrites = (session: Types.Session) =>
  Effect.gen(function* () {
    const apiKeys = yield* ApiKeyService;
    // Outside any session context, as the admin's tooling would mint it.
    const existing = yield* apiKeys.create(user.id, { name: "existing" });
    const asSession = <A, E>(effect: Effect.Effect<A, E>) =>
      Effect.result(
        effect.pipe(Effect.provide(SessionContext.authenticatedLayer({ session, user }))),
      );
    return {
      create: yield* asSession(apiKeys.create(user.id, { name: "new" })),
      update: yield* asSession(apiKeys.update(user.id, existing.apiKey.id, { name: "renamed" })),
      remove: yield* asSession(apiKeys.delete(user.id, existing.apiKey.id)),
    };
  }).pipe(Effect.provide(apiKeyServiceLayer({ users: [user] })), Effect.runPromise);

describe("a guarded service under an impersonation session", () => {
  it("refuses API key creation, changes and deletion", async () => {
    const results = await runApiKeyWrites(impersonation);
    const failures: ReadonlyArray<Result.Result<unknown, { readonly _tag: string }>> = [
      results.create,
      results.update,
      results.remove,
    ];
    Arr.forEach(failures, (result) => {
      assert(Result.isFailure(result));
      expect(result.failure._tag).toBe("ImpersonationForbiddenError");
    });
  });

  it("allows them from the user's own session", async () => {
    const results = await runApiKeyWrites(plain);
    expect(
      Arr.map([results.create, results.update, results.remove], (result) => result._tag),
    ).toEqual(["Success", "Success", "Success"]);
  });
});
