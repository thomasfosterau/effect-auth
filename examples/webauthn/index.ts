/**
 * WebAuthn Passkey Example
 *
 * This example demonstrates how to implement passwordless authentication
 * using WebAuthn passkeys with Effect Auth.
 */

import { Effect, Context } from "effect";
import * as Auth from "effect-auth";

// ============================================================================
// Storage Implementations
// ============================================================================

// In-memory challenge store (use Redis in production)
const challengeMap = new Map<string, Auth.WebAuthnChallenge>();

const challengeStore: Auth.ChallengeStoreShape = {
  create: (challenge) =>
    Effect.sync(() => {
      const key = Buffer.from(challenge.challenge).toString("hex");
      challengeMap.set(key, challenge);
      return challenge;
    }),

  get: (challenge) =>
    Effect.sync(() => {
      const key = Buffer.from(challenge).toString("hex");
      return challengeMap.get(key) ?? null;
    }),

  delete: (challenge) =>
    Effect.sync(() => {
      const key = Buffer.from(challenge).toString("hex");
      challengeMap.delete(key);
    }),
};

// In-memory credential store (use database in production)
const credentialMap = new Map<string, Auth.WebAuthnCredential>();

const credentialStore: Auth.CredentialStoreShape = {
  create: (credential) =>
    Effect.sync(() => {
      credentialMap.set(credential.id, credential);
      console.log(`✅ Stored credential ${credential.id} for user ${credential.userId}`);
      return credential;
    }),

  get: (credentialId) => Effect.sync(() => credentialMap.get(credentialId) ?? null),

  update: (credential) =>
    Effect.sync(() => {
      credentialMap.set(credential.id, credential);
      console.log(`✅ Updated credential ${credential.id} (counter: ${credential.counter})`);
      return credential;
    }),

  delete: (credentialId) =>
    Effect.sync(() => {
      credentialMap.delete(credentialId);
    }),

  listByUserId: (userId) =>
    Effect.sync(() => {
      const credentials = Array.from(credentialMap.values()).filter((c) => c.userId === userId);
      return credentials;
    }),
};

// ============================================================================
// WebAuthn Configuration
// ============================================================================

const webAuthnConfig: Auth.WebAuthnConfig = {
  relyingPartyId: "example.com",
  relyingPartyName: "Example Corp",
  expectedOrigin: "https://example.com",
  challengeExpiresIn: 5 * 60 * 1000, // 5 minutes
};

// ============================================================================
// Example: Registration Flow
// ============================================================================

const registrationExample = Effect.gen(function* () {
  console.log("\n🔐 WebAuthn Registration Example");
  console.log("=".repeat(50));

  const service = yield* Auth.makeWebAuthnService(webAuthnConfig);

  const user: Auth.WebAuthnUser = {
    id: "user-123",
    name: "alice@example.com",
    displayName: "Alice Smith",
  };

  // Step 1: Generate registration challenge
  console.log("\n📝 Step 1: Generate registration challenge");
  const { challenge, expiresAt } = yield* service.generateRegistrationChallenge(user);
  console.log(`  Challenge generated (${challenge.length} bytes)`);
  console.log(`  Expires at: ${new Date(expiresAt).toISOString()}`);
  console.log(`  Base64: ${Buffer.from(challenge).toString("base64").substring(0, 40)}...`);

  // Step 2: Client would create credential here
  console.log("\n🌐 Step 2: Client creates credential (simulated)");
  console.log("  In a real app, the browser's WebAuthn API would:");
  console.log("  - Prompt user for biometric/PIN");
  console.log("  - Generate key pair on authenticator");
  console.log("  - Return attestation response");

  // Note: In a real implementation, the client would:
  // - Call navigator.credentials.create() with the challenge
  // - Return the attestation response to the server
  // - Server would then call verifyRegistration()

  console.log("\n✅ Registration flow initiated successfully!");
  console.log("   Challenge stored and waiting for client response");
});

// ============================================================================
// Example: Authentication Flow
// ============================================================================

const authenticationExample = Effect.gen(function* () {
  console.log("\n🔓 WebAuthn Authentication Example");
  console.log("=".repeat(50));

  const service = yield* Auth.makeWebAuthnService(webAuthnConfig);
  const userId = "user-123";

  // Step 1: Generate authentication challenge
  console.log("\n📝 Step 1: Generate authentication challenge");
  const { challenge, expiresAt } = yield* service.generateAuthenticationChallenge(userId);
  console.log(`  Challenge generated (${challenge.length} bytes)`);
  console.log(`  Expires at: ${new Date(expiresAt).toISOString()}`);
  console.log(`  User ID: ${userId}`);

  // Step 2: Client would sign with credential here
  console.log("\n🌐 Step 2: Client signs with passkey (simulated)");
  console.log("  In a real app, the browser's WebAuthn API would:");
  console.log("  - Prompt user for biometric/PIN");
  console.log("  - Sign challenge with private key");
  console.log("  - Return assertion response");

  // Note: In a real implementation, the client would:
  // - Call navigator.credentials.get() with the challenge
  // - Return the assertion response to the server
  // - Server would then call verifyAuthentication()

  console.log("\n✅ Authentication flow initiated successfully!");
  console.log("   Challenge stored and waiting for client response");
});

// ============================================================================
// Example: Managing Multiple Credentials
// ============================================================================

const multipleCredentialsExample = Effect.gen(function* () {
  console.log("\n📱 Multiple Credentials Example");
  console.log("=".repeat(50));

  const userId = "user-456";

  // Simulate storing multiple credentials
  const credentials: Auth.WebAuthnCredential[] = [
    {
      id: "cred-laptop",
      userId,
      publicKey: new Uint8Array(65),
      algorithm: -7, // ES256
      counter: 5,
      createdAt: Date.now(),
      name: "MacBook Pro",
      transports: ["internal", "usb"],
    },
    {
      id: "cred-phone",
      userId,
      publicKey: new Uint8Array(65),
      algorithm: -7,
      counter: 12,
      createdAt: Date.now(),
      name: "iPhone",
      transports: ["internal", "nfc"],
    },
    {
      id: "cred-yubikey",
      userId,
      publicKey: new Uint8Array(65),
      algorithm: -7,
      counter: 3,
      createdAt: Date.now(),
      name: "YubiKey 5",
      transports: ["usb"],
    },
  ];

  console.log("\n🔑 Storing multiple credentials for user");
  for (const cred of credentials) {
    yield* credentialStore.create(cred);
  }

  console.log("\n📋 Listing user's credentials");
  const userCredentials = yield* credentialStore.listByUserId(userId);
  console.log(`  Found ${userCredentials.length} credentials:`);
  for (const cred of userCredentials) {
    console.log(`    - ${cred.name || cred.id} (counter: ${cred.counter})`);
    if (cred.transports) {
      console.log(`      Transports: ${cred.transports.join(", ")}`);
    }
  }

  console.log("\n✅ User can authenticate with any of these credentials!");
});

// ============================================================================
// Main Program
// ============================================================================

const program = Effect.gen(function* () {
  console.log("\n╔════════════════════════════════════════════════╗");
  console.log("║  Effect Auth - WebAuthn Passkey Examples      ║");
  console.log("╚════════════════════════════════════════════════╝");

  // Run examples
  yield* registrationExample;
  yield* authenticationExample;
  yield* multipleCredentialsExample;

  console.log("\n" + "=".repeat(50));
  console.log("✅ All examples completed successfully!");
  console.log("\n💡 Next steps:");
  console.log("   1. Implement client-side WebAuthn API calls");
  console.log("   2. Connect to a real database for storage");
  console.log("   3. Add session management after authentication");
  console.log("   4. Implement credential management UI");
  console.log("=".repeat(50) + "\n");
});

// Provide dependencies
const dependencies = Context.merge(
  Context.make(Auth.ChallengeStore, challengeStore),
  Context.make(Auth.CredentialStore, credentialStore),
);

// Run the program
Effect.runPromise(Effect.provide(program, dependencies)).catch(console.error);
