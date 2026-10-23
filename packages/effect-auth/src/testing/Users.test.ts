import { describe, expect, it } from "vite-plus/test";
import { Array as Arr, DateTime, Effect, Option, Schema } from "effect";
import * as Admin from "../Admin.ts";
import * as SessionContext from "../SessionContext.ts";
import * as Types from "../Types.ts";
import * as Testing from "./index.ts";

const uuidV4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe("fixtureUsers", () => {
  it("gives an admin and two distinct non-admins, all with UUID ids", () => {
    const users = Testing.fixtureUsers();

    expect(users.admin.id).toBe(Testing.fixtureUserIds.admin);
    expect(users.member.id).toBe(Testing.fixtureUserIds.member);
    expect(users.otherMember.id).toBe(Testing.fixtureUserIds.otherMember);
    Arr.forEach([users.admin, users.member, users.otherMember], (user) => {
      expect(user.id).toMatch(uuidV4);
    });
    expect(new Set([users.admin.id, users.member.id, users.otherMember.id]).size).toBe(3);

    expect(Admin.isAdmin(users.admin)).toBe(true);
    expect(Admin.isAdmin(users.member)).toBe(false);
    expect(Admin.isAdmin(users.otherMember)).toBe(false);
  });

  it("is deterministic", () => {
    expect(Testing.fixtureUsers()).toEqual(Testing.fixtureUsers());
  });

  it("takes id, role and timestamp overrides", () => {
    const createdAt = DateTime.toDateUtc(DateTime.makeUnsafe("2030-01-01T00:00:00.000Z"));
    const users = Testing.fixtureUsers({
      ids: { member: "11111111-1111-4111-8111-111111111111" },
      adminRole: "owner",
      memberRole: "reader",
      createdAt,
    });

    expect(users.member.id).toBe("11111111-1111-4111-8111-111111111111");
    expect(users.admin.id).toBe(Testing.fixtureUserIds.admin);
    expect(users.admin.attributes["role"]).toBe("owner");
    expect(users.otherMember.attributes["role"]).toBe("reader");
    expect(users.admin.createdAt).toEqual(createdAt);
    expect(users.admin.updatedAt).toEqual(createdAt);
  });

  it("are valid User records that survive an encode/decode round trip", () => {
    const users = Testing.fixtureUsers();
    Arr.forEach([users.admin, users.member, users.otherMember], (user) => {
      const row = Schema.encodeSync(Types.User)(user);
      expect(Schema.decodeUnknownSync(Types.User)(row)).toEqual(user);
    });
  });

  it("run as the principal their id names", async () => {
    const users = Testing.fixtureUsers();
    const id = await Effect.runPromise(
      Effect.map(SessionContext.requireCurrentUser, (user) => user.id).pipe(
        Testing.runAs(users.member),
      ),
    );
    expect(id).toBe(Testing.fixtureUserIds.member);
  });
});

describe("fixtureUser", () => {
  it("defaults the id to a fresh UUID", () => {
    const one = Testing.fixtureUser();
    const two = Testing.fixtureUser();

    expect(one.id).toMatch(uuidV4);
    expect(two.id).toMatch(uuidV4);
    expect(one.id).not.toBe(two.id);
    expect(one.createdAt).toEqual(Testing.fixtureEpoch);
    expect(one.attributes).toEqual({});
  });

  it("takes an id, a name, a role and extra attributes", () => {
    const user = Testing.fixtureUser({
      id: "22222222-2222-4222-8222-222222222222",
      name: "Edith",
      role: "editor",
      attributes: { team: "docs", role: "overwritten" },
    });

    expect(user).toEqual({
      id: "22222222-2222-4222-8222-222222222222",
      name: "Edith",
      createdAt: Testing.fixtureEpoch,
      updatedAt: Testing.fixtureEpoch,
      attributes: { team: "docs", role: "editor" },
    });
    expect(SessionContext.withRole()(Testing.sessionFor(user, Testing.fixtureEpoch))).toEqual(
      Option.some({ ...user, role: "editor" }),
    );
  });
});
