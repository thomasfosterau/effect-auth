import { assert, describe, expect, it } from "vite-plus/test";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Layer from "effect/Layer";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Testing from "@thomasfosterau/effect-auth/testing";
import { phoneNumber } from "better-auth/plugins";
import { at, fromNow, makeAuth, rowOf, run, runExit, signUp } from "./testing/Fixtures.ts";
import { BetterAuthInstance } from "./BetterAuth.ts";
import { identifierId, rolesOf } from "./Convert.ts";
import { userStoreLayer } from "./Users.ts";

const failure = (exit: Exit.Exit<unknown, unknown>) =>
  Exit.isFailure(exit) ? Option.getOrUndefined(Exit.findErrorOption(exit)) : undefined;

describe("UserStore conformance", () => {
  const { auth } = makeAuth({
    user: {
      additionalFields: {
        role: { type: "string", required: false },
        nested: { type: "json", required: false },
      },
    },
    plugins: [],
  });
  const suite = Testing.userStoreConformance({
    seedUser: (user) =>
      Effect.tryPromise({
        try: async () => {
          const context = await auth.$context;
          await context.adapter.create({
            model: "user",
            forceAllowId: true,
            data: {
              id: user.id,
              name: user.name ?? null,
              image: user.image ?? null,
              email: `${user.id}@example.test`,
              emailVerified: false,
              createdAt: user.createdAt,
              updatedAt: user.updatedAt,
              ...user.attributes,
            },
          });
        },
        catch: (cause) => new Auth.AuthError({ message: "seeding the user failed", cause }),
      }),
  });
  const layer = userStoreLayer.pipe(Layer.provide(BetterAuthInstance.layer(auth)));
  Arr.forEach(suite.cases, (testCase) => {
    it(testCase.name, () =>
      expect(Effect.runPromise(testCase.run.pipe(Effect.provide(layer)))).resolves.toBeUndefined(),
    );
  });
});

describe("UserService over BetterAuth", () => {
  const users = Effect.service(Auth.UserService);

  it("reads a user with BetterAuth's columns as attributes, email kept off it", async () => {
    const { auth } = makeAuth();
    const { user } = await signUp(auth);
    const read = await run(
      auth,
      Effect.flatMap(users, (s) => s.getUser(user.id)),
    );
    expect(read).toMatchObject({ id: user.id, name: "Ada" });
    expect(read.attributes["role"]).toBe("user");
    expect(read.attributes).not.toHaveProperty("email");
    const missing = await runExit(
      auth,
      Effect.flatMap(users, (s) => s.getUser("nobody")),
    );
    expect(failure(missing)).toBeInstanceOf(Auth.UserNotFoundError);
  });

  it("updates the name and image, and declared columns only", async () => {
    const { auth, db } = makeAuth();
    const { user } = await signUp(auth);
    const renamed = await run(
      auth,
      Effect.flatMap(users, (s) =>
        s.updateUser(user.id, { name: "Grace", image: "https://x.test/g.png" }),
      ),
    );
    expect(renamed).toMatchObject({ name: "Grace", image: "https://x.test/g.png" });
    const planned = await run(
      auth,
      Effect.flatMap(users, (s) => s.updateUserAttributes(user.id, { plan: "pro" })),
    );
    expect(planned.attributes["plan"]).toBe("pro");
    expect(db["user"]?.[0]?.["plan"]).toBe("pro");

    const undeclared = await runExit(
      auth,
      Effect.flatMap(users, (s) => s.updateUserAttributes(user.id, { favourite: "blue" })),
    );
    expect(failure(undeclared)).toBeInstanceOf(Auth.AuthError);
  });

  it("refuses server-only and standing attributes, as the core does", async () => {
    const { auth } = makeAuth();
    const { user } = await signUp(auth);
    const refused = await Promise.all(
      Arr.map(["role", "banned", "banExpires"], (key) =>
        runExit(
          auth,
          Effect.flatMap(users, (s) => s.updateUserAttributes(user.id, { [key]: "admin" })),
        ),
      ),
    );
    Arr.forEach(refused, (exit) => expect(failure(exit)).toBeInstanceOf(Auth.InvalidInputError));
  });

  it("keeps a Date column unwritten when an unrelated attribute changes", async () => {
    const { auth, db } = makeAuth();
    const { user } = await signUp(auth);
    const row = rowOf(db, "user");
    const expires = fromNow(60_000);
    row["banExpires"] = expires;
    await run(
      auth,
      Effect.flatMap(users, (s) => s.updateUserAttributes(user.id, { plan: "pro" })),
    );
    expect(row["banExpires"]).toEqual(expires);
  });

  it("deletes the user, its sessions and its accounts", async () => {
    const { auth, db } = makeAuth();
    const a = await signUp(auth);
    const b = await signUp(auth);
    await run(
      auth,
      Effect.flatMap(users, (s) => s.deleteUser(a.user.id)),
    );
    expect(db["user"]?.map((u) => u["id"])).toEqual([b.user.id]);
    expect(db["session"]?.map((s) => s["userId"])).toEqual([b.user.id]);
    expect(db["account"]?.map((s) => s["userId"])).toEqual([b.user.id]);
  });
});

describe("IdentifierStore over BetterAuth", () => {
  const identifiers = Effect.service(Auth.IdentifierStore);

  it("derives the email and username identifiers with deterministic ids", async () => {
    const { auth } = makeAuth();
    const { user, email } = await signUp(auth);
    const context = await auth.$context;
    await context.internalAdapter.updateUser(user.id, { username: "ada" });
    const listed = await run(
      auth,
      Effect.flatMap(identifiers, (s) => s.listByUser(user.id)),
    );
    expect(listed.map((i) => [i.id, i.type, i.value, i.verified])).toEqual([
      [identifierId(user.id, "email"), "email", email, false],
      [identifierId(user.id, "username"), "username", "ada", true],
    ]);
    const byEmail = await run(
      auth,
      Effect.flatMap(identifiers, (s) => Auth.lookupIdentifier(s, "email", email)),
    );
    expect(Option.getOrUndefined(byEmail)?.userId).toBe(user.id);
    const byUsername = await run(
      auth,
      Effect.flatMap(identifiers, (s) => Auth.lookupIdentifier(s, "username", "ada")),
    );
    expect(Option.getOrUndefined(byUsername)?.userId).toBe(user.id);
    const none = await run(
      auth,
      Effect.flatMap(identifiers, (s) => Auth.lookupIdentifier(s, "phone", "+15550100")),
    );
    expect(Option.isNone(none)).toBe(true);
  });

  it("derives and finds the phoneNumber() plugin's number, and verifies it", async () => {
    const { auth } = makeAuth({ plugins: [phoneNumber()] });
    const { user } = await signUp(auth);
    const context = await auth.$context;
    await context.internalAdapter.updateUser(user.id, { phoneNumber: "+15550100" });
    const found = await run(
      auth,
      Effect.flatMap(identifiers, (s) => Auth.lookupIdentifier(s, "phone", "+15550100")),
    );
    expect(Option.getOrUndefined(found)).toMatchObject({
      id: identifierId(user.id, "phone"),
      verified: false,
    });
    const verified = await run(
      auth,
      Effect.flatMap(identifiers, (s) => s.setVerified(identifierId(user.id, "phone"), fromNow(0))),
    );
    expect(Option.getOrUndefined(verified)?.verified).toBe(true);
    // Without the username() plugin there is no column to look a username up by.
    const none = await run(
      auth,
      Effect.flatMap(identifiers, (s) => Auth.lookupIdentifier(s, "username", "ada")),
    );
    expect(Option.isNone(none)).toBe(true);
  });

  it("marks the email verified", async () => {
    const { auth, db } = makeAuth();
    const { user } = await signUp(auth);
    const verified = await run(
      auth,
      Effect.flatMap(identifiers, (s) => s.setVerified(identifierId(user.id, "email"), fromNow(0))),
    );
    expect(Option.getOrUndefined(verified)?.verified).toBe(true);
    expect(db["user"]?.[0]?.["emailVerified"]).toBe(true);
    const unknown = await run(
      auth,
      Effect.flatMap(identifiers, (s) => s.setVerified("not-derived", fromNow(0))),
    );
    expect(Option.isNone(unknown)).toBe(true);
  });

  it("refuses every write that would skip BetterAuth's verification", async () => {
    const { auth, db } = makeAuth();
    const { user, email } = await signUp(auth);
    const [current] = await run(
      auth,
      Effect.flatMap(identifiers, (s) => s.listByUser(user.id)),
    );
    assert(current !== undefined, "the email identifier is derived");
    const next = { ...current, id: "other", value: "attacker@example.test" };
    const create = await runExit(
      auth,
      Effect.flatMap(identifiers, (s) => s.create(next)),
    );
    expect(failure(create)).toBeInstanceOf(Auth.IdentifierRefusedError);
    const writes: ReadonlyArray<
      (s: typeof Auth.IdentifierStore.Service) => Effect.Effect<unknown, Auth.AuthError>
    > = [
      (s) => s.replace(current, next),
      (s) => s.delete(current.id),
      (s) => s.deleteByUser(user.id),
    ];
    const refused = await Promise.all(
      Arr.map(writes, (write) => runExit(auth, Effect.flatMap(identifiers, write))),
    );
    Arr.forEach(refused, (exit) => expect(failure(exit)).toBeInstanceOf(Auth.AuthError));
    expect(db["user"]?.[0]?.["email"]).toBe(email);
  });
});

const user = (role: Auth.Json): Auth.User => ({
  id: "u",
  createdAt: at(0),
  updatedAt: at(0),
  attributes: { role },
});

describe("rolesOf", () => {
  it("splits the admin plugin's comma-separated roles", () => {
    expect(rolesOf(user("admin, user"))).toEqual(["admin", "user"]);
    expect(rolesOf(user("admin"))).toEqual(["admin"]);
    expect(rolesOf(user(",,"))).toEqual([]);
    expect(rolesOf(user(null))).toEqual([]);
  });
});
