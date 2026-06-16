/**
 * WorkOS Integration Example
 *
 * Demonstrates `@effect-auth/workos`: an Effect-native facade over the WorkOS
 * Node SDK that exposes the entire WorkOS feature set. Every WorkOS module
 * (`sso`, `userManagement`, `directorySync`, `organizations`, `webhooks`,
 * `authorization`, ...) is available as `Effect`-returning methods.
 *
 * The default run only performs **synchronous** URL generation, so it is safe
 * to run without real credentials and without making any network calls:
 *
 *   bun run index.ts
 *
 * The exported helpers below show how the live API calls look. Provide real
 * `WORKOS_API_KEY` / `WORKOS_CLIENT_ID` values and call them to hit WorkOS.
 */

import { Effect } from "effect";
import { WorkOS } from "@effect-auth/workos";

// =============================================================================
// Layer
// =============================================================================

const CLIENT_ID = process.env.WORKOS_CLIENT_ID ?? "client_placeholder";
const REDIRECT_URI = process.env.WORKOS_REDIRECT_URI ?? "http://localhost:3000/callback";

/**
 * Build the WorkOS layer from options. In a real app prefer `WorkOS.layer`,
 * which reads `WORKOS_API_KEY` / `WORKOS_CLIENT_ID` from the environment via
 * Effect `Config`.
 */
const WorkOSLayer = WorkOS.layerOptions({
  apiKey: process.env.WORKOS_API_KEY ?? "sk_test_placeholder",
  clientId: CLIENT_ID,
});

// =============================================================================
// 1. AuthKit / SSO authorization URLs (synchronous — no network)
// =============================================================================

const authKitAuthorizationUrl = Effect.gen(function* () {
  const workos = yield* WorkOS;
  const url = yield* workos.userManagement.getAuthorizationUrl({
    provider: "authkit",
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
  });

  console.log("\n=== AuthKit Authorization URL ===");
  console.log("Redirect the user here to start hosted authentication:");
  console.log(url);
  return url;
});

const ssoAuthorizationUrl = (organizationId: string) =>
  Effect.gen(function* () {
    const workos = yield* WorkOS;
    const url = yield* workos.sso.getAuthorizationUrl({
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      organization: organizationId,
    });

    console.log("\n=== Enterprise SSO Authorization URL ===");
    console.log(`Organization: ${organizationId}`);
    console.log(url);
    return url;
  });

// =============================================================================
// 2. Authenticate a user (AuthKit) — live network call
// =============================================================================

export const authenticateWithPassword = (email: string, password: string) =>
  Effect.gen(function* () {
    const workos = yield* WorkOS;

    console.log("\n=== Authenticate With Password ===");
    const response = yield* workos.userManagement.authenticateWithPassword({
      clientId: CLIENT_ID,
      email,
      password,
    });

    console.log("Authenticated user:", response.user.email);
    console.log("Access token (truncated):", response.accessToken.slice(0, 16) + "...");
    return response;
  }).pipe(
    // WorkOS surfaces every failure as a single `WorkOSError`.
    Effect.catchTag("WorkOSError", (error) => {
      console.error(`Authentication failed [${error.status ?? "?"}]:`, error.message);
      if (error.authenticationCode) {
        // e.g. "mfa_challenge", "email_verification_required", ...
        console.error("Additional step required:", error.authenticationCode);
        console.error("Pending token:", error.pendingAuthenticationToken);
      }
      return Effect.fail(error);
    }),
  );

// =============================================================================
// 3. User Management & Organizations — live network calls
// =============================================================================

export const listUsers = Effect.gen(function* () {
  const workos = yield* WorkOS;
  console.log("\n=== List Users ===");
  const page = yield* workos.userManagement.listUsers();
  for (const user of page.data) {
    console.log(`- ${user.id}: ${user.email}`);
  }
  return page.data;
});

export const createOrganization = (name: string) =>
  Effect.gen(function* () {
    const workos = yield* WorkOS;
    console.log("\n=== Create Organization ===");
    const organization = yield* workos.organizations.createOrganization({ name });
    console.log("Created organization:", organization.id, organization.name);
    return organization;
  });

export const sendMagicAuth = (email: string) =>
  Effect.gen(function* () {
    const workos = yield* WorkOS;
    console.log("\n=== Send Magic Auth Code ===");
    const result = yield* workos.userManagement.createMagicAuth({ email });
    console.log("Magic Auth challenge created for:", result.email);
    return result;
  });

// =============================================================================
// 4. Directory Sync (SCIM) — live network call
// =============================================================================

export const listDirectories = Effect.gen(function* () {
  const workos = yield* WorkOS;
  console.log("\n=== List Directories (SCIM) ===");
  const page = yield* workos.directorySync.listDirectories();
  for (const directory of page.data) {
    console.log(`- ${directory.id}: ${directory.name} (${directory.state})`);
  }
  return page.data;
});

// =============================================================================
// 5. Webhooks — signature verification + parsing
// =============================================================================

export const verifyWebhook = (payload: string, signature: string, secret: string) =>
  Effect.gen(function* () {
    const workos = yield* WorkOS;
    console.log("\n=== Verify Webhook ===");
    const event = yield* workos.webhooks.constructEvent({
      payload,
      sigHeader: signature,
      secret,
    });
    console.log("Verified event:", event.event);
    return event;
  });

// =============================================================================
// 6. Escape hatch — call any endpoint via the raw client
// =============================================================================

export const rawApiCall = Effect.gen(function* () {
  const workos = yield* WorkOS;
  // `use` lifts any client call into an Effect, mapping errors to WorkOSError.
  return yield* workos.use((client) => client.get("/organizations"));
});

// =============================================================================
// Run
// =============================================================================

const runExample = Effect.gen(function* () {
  console.log("=".repeat(70));
  console.log("WorkOS Integration Example (@effect-auth/workos)");
  console.log("=".repeat(70));

  // Synchronous, network-free demonstrations.
  yield* authKitAuthorizationUrl;
  yield* ssoAuthorizationUrl("org_example_123");

  console.log("\n=== Full feature set available on the WorkOS service ===");
  console.log(
    [
      "sso",
      "userManagement (AuthKit)",
      "directorySync (SCIM)",
      "organizations",
      "organizationDomains",
      "multiFactorAuth",
      "passwordless",
      "auditLogs",
      "events",
      "webhooks",
      "authorization (FGA)",
      "vault",
      "widgets",
      "adminPortal",
      "actions",
      "apiKeys",
      "connect",
      "featureFlags",
      "groups",
      "pipes",
      "radar",
    ]
      .map((m) => `  • workos.${m}`)
      .join("\n"),
  );

  // Live calls require real credentials — uncomment to try them:
  //
  // yield* authenticateWithPassword("user@example.com", "correct horse battery staple")
  // yield* listUsers
  // yield* createOrganization("Acme Inc.")
  // yield* sendMagicAuth("user@example.com")
  // yield* listDirectories
  // yield* rawApiCall

  console.log("\n" + "=".repeat(70));
  console.log("Example completed!");
  console.log("=".repeat(70));
});

Effect.runPromise(runExample.pipe(Effect.provide(WorkOSLayer)))
  .then(() => {
    console.log("\n✓ WorkOS example completed successfully");
  })
  .catch((error: unknown) => {
    console.error("\n✗ Error:", error);
    process.exit(1);
  });
