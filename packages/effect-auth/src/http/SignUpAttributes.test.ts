/**
 * Sign-up attributes over HTTP (#580): `POST /users` keeps only the keys
 * `signUpAttributes` allows, the services strip the authority-bearing ones
 * whatever it allows, and the kept bag is size-limited. Run against the real
 * `Http.make` handler over the in-memory `./client/testing` fixture.
 */
import { assert, describe, expect, it } from "vite-plus/test";
import { MutableHashMap } from "effect";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import { isAdmin } from "../Admin.ts";
import { makeServerFixture, type ServerFixtureOptions } from "../client/testing/fixture.ts";
import { SIGN_UP_ATTRIBUTES_MAX_BYTES } from "./HttpServer.ts";

const PW = "password-123";

const toJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

const signUpRequest = (fields: { readonly [key: string]: Schema.Json }) =>
  new Request("http://client.test/users", {
    method: "POST",
    headers: { "content-type": "application/vnd.api+json" },
    body: toJson({ data: { type: "users", attributes: fields } }),
  });

/** The `users` resource a `201` sign-up includes. */
const SignUpAnswer = Schema.Struct({
  included: Schema.Array(
    Schema.Struct({
      type: Schema.String,
      id: Schema.String,
      attributes: Schema.Struct({ attributes: Schema.Record(Schema.String, Schema.Json) }),
    }),
  ),
});

/** Sign up over HTTP with `attributes`; the response's user and the stored one. */
const signUpWith = async (
  attributes: { readonly [key: string]: Schema.Json },
  options: ServerFixtureOptions = {},
) => {
  const server = makeServerFixture(options);
  const response = await server.handler(
    signUpRequest({ email: "mallory@example.com", password: PW, attributes }),
  );
  expect(response.status).toBe(201);
  const answer = Schema.decodeUnknownSync(SignUpAnswer)(await response.json());
  const user = answer.included.find((resource) => resource.type === "users");
  assert(user !== undefined, "the sign-up includes its user");
  const stored = Option.getOrUndefined(MutableHashMap.get(server.usersById, user.id));
  assert(stored !== undefined, "the sign-up stored its user");
  return { answered: user.attributes.attributes, stored };
};

/** Every key the services strip, whatever the allow-list names. */
const PROTECTED = {
  role: "admin",
  banned: false,
  banReason: "none",
  banExpires: 0,
  scimUserName: "ceo",
  scimDeactivated: false,
  scimExternalId: "idp-1",
  isAnonymous: true,
};

describe("POST /users attributes (#580)", () => {
  it("an unauthenticated sign-up with role: admin does not create an admin", async () => {
    const { answered, stored } = await signUpWith({ role: "admin" });

    expect(answered).toEqual({});
    expect(stored.attributes).toEqual({});
    expect(stored.attributes["role"]).toBeUndefined();
    expect(isAdmin(stored)).toBe(false);
  });

  it("keeps no attribute by default, without refusing the sign-up", async () => {
    const { answered, stored } = await signUpWith({ plan: "pro", theme: "dark" });

    expect(answered).toEqual({});
    expect(stored.attributes).toEqual({});
  });

  it("keeps the keys signUpAttributes allows and drops the rest", async () => {
    const { answered, stored } = await signUpWith(
      { plan: "pro", theme: "dark", role: "admin" },
      { signUpAttributes: ["plan"] },
    );

    expect(answered).toEqual({ plan: "pro" });
    expect(stored.attributes).toEqual({ plan: "pro" });
  });

  it("never keeps the role, ban, SCIM or anonymous keys, even when signUpAttributes names them", async () => {
    const { answered, stored } = await signUpWith(
      { ...PROTECTED, plan: "pro" },
      { signUpAttributes: [...R.keys(PROTECTED), "plan"] },
    );

    expect(answered).toEqual({ plan: "pro" });
    expect(stored.attributes).toEqual({ plan: "pro" });
    expect(isAdmin(stored)).toBe(false);
  });

  it(`refuses kept attributes over ${SIGN_UP_ATTRIBUTES_MAX_BYTES} bytes with 400, and creates no user`, async () => {
    const server = makeServerFixture({ signUpAttributes: ["bio"] });
    const response = await server.handler(
      signUpRequest({
        email: "big@example.com",
        password: PW,
        // Multi-byte characters: the limit counts UTF-8 bytes, not characters.
        attributes: { bio: "é".repeat(SIGN_UP_ATTRIBUTES_MAX_BYTES / 2) },
      }),
    );

    expect(response.status).toBe(400);
    expect(MutableHashMap.size(server.usersById)).toBe(0);
  });

  it("accepts kept attributes within the limit, and never counts dropped keys", async () => {
    const { stored } = await signUpWith(
      { bio: "x".repeat(SIGN_UP_ATTRIBUTES_MAX_BYTES - 64), padding: "y".repeat(16_384) },
      { signUpAttributes: ["bio"] },
    );

    expect(R.keys(stored.attributes)).toEqual(["bio"]);
  });
});
