/**
 * Fixture users whose ids are UUIDs, so an app whose tables reference
 * `users.id` as `uuid NOT NULL` can insert them as real rows (through its own
 * `UserStore` or seed) and run as them with `runAs`.
 *
 * @module testing
 */
import type * as Types from "../Types.ts";

/**
 * The canonical fixtures' ids: fixed, valid version-4 UUIDs, so a test can
 * name them in SQL or a snapshot without threading the generated value.
 *
 * @since 1.0.0
 * @category constants
 */
export const fixtureUserIds = {
  admin: "00000000-0000-4000-8000-00000000a001",
  member: "00000000-0000-4000-8000-00000000b001",
  otherMember: "00000000-0000-4000-8000-00000000b002",
} as const;

/**
 * When the fixtures were created, unless a test says otherwise: a fixed
 * instant, so records compare equal across runs.
 *
 * @since 1.0.0
 * @category constants
 */
export const fixtureEpoch: Date = new Date("2026-01-01T00:00:00.000Z");

/**
 * A fixture user's fields. Everything is optional.
 *
 * @since 1.0.0
 * @category models
 */
export interface FixtureUserOptions {
  /** Defaults to a fresh random UUID. */
  readonly id?: string | undefined;
  /** Written to `attributes.role`, where `Admin.isAdmin` and `SessionContext.withRole` read it. */
  readonly role?: string | undefined;
  readonly name?: string | undefined;
  /** Merged under `role`. */
  readonly attributes?: Types.Attributes | undefined;
  /** `createdAt` and `updatedAt`; defaults to {@link fixtureEpoch}. */
  readonly createdAt?: Date | undefined;
}

/**
 * One fixture user. Its id is a fresh random UUID unless `id` is given.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import * as Testing from "@thomasfosterau/effect-auth/testing"
 *
 * const editor = Testing.fixtureUser({ role: "editor", name: "Edith" })
 * assert.match(editor.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
 * assert.equal(editor.attributes["role"], "editor")
 * ```
 *
 * @since 1.0.0
 * @category constructors
 */
export const fixtureUser = (options: FixtureUserOptions = {}): Types.User => {
  const createdAt = options.createdAt ?? fixtureEpoch;
  return {
    id: options.id ?? globalThis.crypto.randomUUID(),
    ...(options.name === undefined ? {} : { name: options.name }),
    createdAt,
    updatedAt: createdAt,
    attributes: {
      ...options.attributes,
      ...(options.role === undefined ? {} : { role: options.role }),
    },
  };
};

/**
 * The canonical trio: an admin, a non-admin, and a second non-admin for
 * cross-author checks ("may a member edit another member's post?").
 *
 * @since 1.0.0
 * @category models
 */
export interface FixtureUsers {
  readonly admin: Types.User;
  readonly member: Types.User;
  readonly otherMember: Types.User;
}

/**
 * Options for {@link fixtureUsers}.
 *
 * @since 1.0.0
 * @category models
 */
export interface FixtureUsersOptions {
  /** Override any of the ids; the rest keep {@link fixtureUserIds}. */
  readonly ids?: Partial<Record<keyof FixtureUsers, string>> | undefined;
  /** The admin's role. Defaults to `"admin"`, which `Admin.isAdmin` recognises by default. */
  readonly adminRole?: string | undefined;
  /** The members' role. Defaults to `"user"`. */
  readonly memberRole?: string | undefined;
  /** `createdAt` and `updatedAt`; defaults to {@link fixtureEpoch}. */
  readonly createdAt?: Date | undefined;
}

/**
 * The canonical fixture users, with UUID ids ({@link fixtureUserIds} unless
 * overridden) and the role in `attributes.role`.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 * import * as Testing from "@thomasfosterau/effect-auth/testing"
 *
 * const users = Testing.fixtureUsers()
 * assert.equal(users.admin.id, Testing.fixtureUserIds.admin)
 * assert.ok(Auth.isAdmin(users.admin))
 * assert.ok(!Auth.isAdmin(users.member))
 *
 * const whoAmI = Effect.map(Auth.SessionContext.requireCurrentUser, (user) => user.id)
 * assert.equal(
 *   await Effect.runPromise(whoAmI.pipe(Testing.runAs(users.otherMember))),
 *   Testing.fixtureUserIds.otherMember,
 * )
 * ```
 *
 * @since 1.0.0
 * @category constructors
 */
export const fixtureUsers = (options: FixtureUsersOptions = {}): FixtureUsers => {
  const ids = { ...fixtureUserIds, ...options.ids };
  const memberRole = options.memberRole ?? "user";
  const createdAt = options.createdAt;
  return {
    admin: fixtureUser({
      id: ids.admin,
      name: "Admin",
      role: options.adminRole ?? "admin",
      createdAt,
    }),
    member: fixtureUser({ id: ids.member, name: "Member", role: memberRole, createdAt }),
    otherMember: fixtureUser({
      id: ids.otherMember,
      name: "Other Member",
      role: memberRole,
      createdAt,
    }),
  };
};
