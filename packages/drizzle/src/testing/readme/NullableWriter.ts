// README:begin
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// `email` nullable: a user created without an address gets `NULL`.
const createUser: (typeof Auth.Email.EmailPasswordStore.Service)["createUser"] = (input) =>
  Effect.gen(function* () {
    const email = input.identifier?.type === "email" ? input.identifier : undefined;
    const id = crypto.randomUUID();
    const now = new Date();
    yield* Effect.tryPromise({
      try: () =>
        db.insert(appUsers).values({
          userId: id,
          name: input.name ?? null,
          email: email?.value ?? null,
          emailVerified: email?.verified ?? false,
          emailVerifiedAt: email?.verifiedAt ?? null, // only if the table maps it
          createdAt: now,
          updatedAt: now,
        }),
      catch: (cause) => new Auth.AuthError({ message: "insert into users failed", cause }),
    });
    // A plain INSERT: when it succeeds, this call created the user.
    return { user: { id, createdAt: now, updatedAt: now, attributes: {} }, created: true };
  });
// README:end

import { db, nullableUsers as appUsers } from "./tables.ts";

/** The README's nullable writer (#406). */
export { createUser };
