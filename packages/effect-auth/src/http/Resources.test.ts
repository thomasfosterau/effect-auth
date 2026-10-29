import { describe, expect, it } from "vite-plus/test";
import { Array as Arr, Order, Record as Rec } from "effect";
import { Resource } from "@thomasfosterau/effect-jsonapi";
import { Identifier } from "../Identifier.ts";
import { Session, User } from "../Types.ts";
import * as Resources from "./Resources.ts";

/** The keys of a record, sorted. */
const sorted = (keys: Iterable<string>): ReadonlyArray<string> =>
  Arr.sort(Arr.fromIterable(keys), Order.String);

/**
 * The fields a resource carries, named as the store-facing record names them:
 * its declared attributes (renamed where JSON:API reserves the name), its id,
 * and each to-one relationship as the foreign key it stands for.
 */
const storeFacingKeys = (
  resource: Resource.Any,
  options: {
    readonly renamed?: Readonly<Record<string, string>>;
    readonly foreignKeys?: Readonly<Record<string, string>>;
    readonly derived?: ReadonlyArray<string>;
  } = {},
): ReadonlyArray<string> =>
  sorted([
    "id",
    ...Rec.keys(Resource.declaredAttributes(resource))
      .filter((key) => !(options.derived ?? []).includes(key))
      .map((key) => options.renamed?.[key] ?? key),
    ...Rec.values(options.foreignKeys ?? {}),
  ]);

// One declaration per entity (#205): each resource is the wire projection of
// a store-facing schema, so a field added to one and not the other fails here.
describe("the JSON:API resources", () => {
  it("users carry exactly Types.User, plus the derived email fields", () => {
    expect(storeFacingKeys(Resources.User, { derived: ["email", "emailVerified"] })).toStrictEqual(
      sorted(Rec.keys(User.fields)),
    );
  });

  it("sessions carry exactly Types.Session, userId as the user relationship", () => {
    expect(storeFacingKeys(Resources.Session, { foreignKeys: { user: "userId" } })).toStrictEqual(
      sorted(Rec.keys(Session.fields)),
    );
  });

  it("identifiers carry exactly Identifier, type as kind and userId as the user relationship", () => {
    expect(
      storeFacingKeys(Resources.Identifier, {
        renamed: { kind: "type" },
        foreignKeys: { user: "userId" },
      }),
    ).toStrictEqual(sorted(Rec.keys(Identifier.fields)));
  });

  it("accepts no write to the attributes bag (#193)", () => {
    // Only `name` and `image` are writable, and only on update.
    expect(sorted(Rec.keys(Resources.User.updateInput.fields))).toStrictEqual(
      sorted(["id", "name", "image"]),
    );
  });
});
