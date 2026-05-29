/**
 * Northwind Traders — end-to-end scenario.
 *
 * Run with: `bun run examples/northwind-traders/main.ts`
 *
 * The scenario walks through:
 *   1. Seed an Admin employee and Northwind catalog data.
 *   2. Sign-up a new Sales Representative (email verification required).
 *   3. Capture the verification token and verify the email.
 *   4. Validate the auto-issued session.
 *   5. Trip the login rate-limiter with bad passwords.
 *   6. SalesRep places an order (permission granted).
 *   7. SalesRep tries to discontinue a product (permission denied).
 *   8. Admin discontinues the product (permission granted).
 *   9. Generate a GitHub OAuth authorization URL.
 *  10. Sign out and confirm the session is gone.
 */

import { Effect } from "effect";
import * as Auth from "effect-auth";
import { ADMIN_EMPLOYEE_ID, consumeCapturedToken, seedNorthwind, userRoles } from "./domain.ts";
import { AppLayer } from "./layers.ts";
import { NorthwindServiceTag } from "./northwind.ts";

const banner = (title: string): void => {
  console.log("\n" + "─".repeat(72));
  console.log(`  ${title}`);
  console.log("─".repeat(72));
};

const signInWithRateLimit = (input: Auth.SignInInput) =>
  Effect.gen(function* () {
    const rateLimiter = yield* Auth.RateLimiterTag;
    const lifecycle = yield* Auth.AuthLifecycleServiceTag;
    yield* rateLimiter.consumeToken(`login:${input.email}`, Auth.RateLimitPresets.login);
    return yield* lifecycle.signIn(input);
  });

const scenario = Effect.gen(function* () {
  banner("Step 1 — Seed Northwind");
  seedNorthwind();
  const hasher = yield* Auth.PasswordHasherTag;
  const adminPassword = yield* hasher.hash("admin-pass-123");
  // Bypass the EmailPasswordStore here because the admin already exists from the seed.
  const emailPasswordStore = yield* Auth.EmailPasswordStoreTag;
  yield* emailPasswordStore.setPasswordHash(ADMIN_EMPLOYEE_ID, adminPassword.hash);
  console.log(
    `Admin '${ADMIN_EMPLOYEE_ID}' seeded with roles: ${userRoles.get(ADMIN_EMPLOYEE_ID)?.join(", ")}`,
  );
  console.log(`Catalog has 3 products across 2 categories.`);

  banner("Step 2 — Sign up a new Sales Representative");
  const lifecycle = yield* Auth.AuthLifecycleServiceTag;
  const signUpResult = yield* lifecycle.signUp({
    email: "nancy.davolio@northwind.example",
    password: "totally-secret-2024",
    name: "Nancy Davolio",
  });
  const salesRep = signUpResult.user;
  console.log(`Created user ${salesRep.id} (${salesRep.attributes["email"]})`);
  console.log(`Needs email verification: ${signUpResult.needsEmailVerification}`);
  console.log(`Roles: ${userRoles.get(salesRep.id)?.join(", ")}`);

  banner("Step 3 — Verify email");
  const token = consumeCapturedToken();
  console.log(`Captured verification token: ${token.slice(0, 16)}…`);
  const verifyResult = yield* lifecycle.verifyEmail({ token });
  if (!verifyResult.session) {
    return yield* new Auth.AuthError({
      message: "Expected auto sign-in after verification",
    });
  }
  const session = verifyResult.session;
  console.log(
    `Verified. Session ${session.id.slice(0, 8)}… issued for ${verifyResult.user.attributes["email"]}`,
  );

  banner("Step 4 — Validate session");
  const sessionManager = yield* Auth.SessionManagerTag;
  const validated = yield* sessionManager.validateSession(session.id);
  console.log(
    `Session valid for ${validated.user.attributes["name"]}, expires at ${validated.session.expiresAt.toISOString()}`,
  );

  banner("Step 5 — Trip the login rate limiter");
  for (let attempt = 1; attempt <= 6; attempt++) {
    const result = yield* Effect.result(
      signInWithRateLimit({
        email: "nancy.davolio@northwind.example",
        password: "wrong-password",
      }),
    );
    if (result._tag === "Failure") {
      console.log(`  attempt ${attempt}: ${result.failure._tag} — ${result.failure.message}`);
    } else {
      console.log(`  attempt ${attempt}: unexpected success`);
    }
  }

  banner("Step 6 — SalesRep places an order");
  const northwind = yield* NorthwindServiceTag;
  const order = yield* northwind.placeOrder(salesRep.id, {
    customerId: "cust-around-horn",
    items: [
      { productId: "prod-chai", quantity: 10 },
      { productId: "prod-tofu", quantity: 4 },
    ],
  });
  const total = order.details.reduce((sum, d) => sum + d.quantity * d.unitPrice, 0);
  console.log(
    `Order ${order.id} placed by ${salesRep.id} — ${order.details.length} line items, total $${total.toFixed(2)}`,
  );

  banner("Step 7 — SalesRep tries to discontinue a product (denied)");
  const denied = yield* Effect.result(northwind.discontinueProduct(salesRep.id, "prod-chang"));
  if (denied._tag === "Failure") {
    console.log(`  Denied: ${denied.failure._tag} — ${denied.failure.message}`);
  } else {
    console.log(`  Unexpectedly succeeded`);
  }

  banner("Step 8 — Admin discontinues the product");
  const discontinued = yield* northwind.discontinueProduct(ADMIN_EMPLOYEE_ID, "prod-chang");
  console.log(`Admin discontinued product ${discontinued.id} (${discontinued.name})`);

  banner("Step 9 — Generate OAuth authorization URL (GitHub)");
  const oauth = yield* Auth.OAuthServiceTag;
  const { url, state } = yield* oauth.generateAuthorizationUrl("github", {
    scopes: ["user:email"],
  });
  console.log(`Redirect the user to: ${url}`);
  console.log(
    `Persisted state '${state.slice(0, 12)}…' — would be checked on /auth/github/callback`,
  );

  banner("Step 10 — Sign out");
  yield* sessionManager.invalidateSession(session.id);
  const afterSignOut = yield* Effect.result(sessionManager.validateSession(session.id));
  if (afterSignOut._tag === "Failure") {
    console.log(`  Session invalidated: ${afterSignOut.failure._tag}`);
  } else {
    console.log(`  Session unexpectedly still valid`);
  }

  console.log("\nNorthwind scenario complete.");
});

Effect.runPromise(Effect.provide(scenario, AppLayer)).catch((error) => {
  console.error("\nScenario failed:", error);
  process.exit(1);
});
