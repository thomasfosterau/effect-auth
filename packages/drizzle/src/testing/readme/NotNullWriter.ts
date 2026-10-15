// README:begin
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// `email` NOT NULL: the row can't be inserted without the address.
const createUser: (typeof Auth.Email.EmailPasswordStore.Service)["createUser"] = (input) =>
  Effect.gen(function* () {
    const email = input.identifier;
    if (email?.type !== "email") {
      return yield* new Auth.AuthError({ message: "A user needs an email address" });
    }
    const id = crypto.randomUUID();
    const now = new Date();
    yield* Effect.tryPromise({
      try: () =>
        db.insert(appUsers).values({
          userId: id,
          name: input.name ?? null,
          email: email.value,
          emailVerified: email.verified,
          emailVerifiedAt: email.verifiedAt ?? null, // only if the table maps it
          createdAt: now,
          updatedAt: now,
        }),
      catch: (cause) => new Auth.AuthError({ message: "insert into users failed", cause }),
    });
    // A plain INSERT: when it succeeds, this call created the user.
    return { user: { id, createdAt: now, updatedAt: now, attributes: {} }, created: true };
  });
// README:end

import { db, notNullUsers as appUsers } from "./tables.ts";

/** The README's NOT NULL writer (#406). */
export { createUser };
