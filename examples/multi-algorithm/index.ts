/**
 * Multi-Algorithm Password Hashing Example
 *
 * This example demonstrates how to use the multi-algorithm password verifier,
 * which is inspired by Rust's password_hash crate design.
 *
 * This pattern is useful for:
 * - Migrating between password hashing algorithms
 * - Supporting multiple algorithms in the same database
 * - Upgrading security without breaking existing user accounts
 */

import { Effect, Context } from "effect-auth";
import * as Auth from "effect-auth";

// Simulate users with different hash algorithms in the database
const users = new Map([
  // Old user with PBKDF2 hash
  [
    "user1",
    {
      id: "user1",
      email: "olduser@example.com",
      // This would be an actual PBKDF2 hash in production
      passwordHash: "", // Will be set below
    },
  ],
  // Newer user also with PBKDF2
  [
    "user2",
    {
      id: "user2",
      email: "newuser@example.com",
      passwordHash: "", // Will be set below
    },
  ],
]);

const multiAlgorithmExample = Effect.gen(function* () {
  console.log("🔐 Multi-Algorithm Password Hashing Example\n");
  console.log("Inspired by Rust's password_hash crate design\n");
  console.log("=".repeat(50) + "\n");

  // Create password hashers
  const pbkdf2Hasher = Auth.makePBKDF2Hasher();

  console.log("1️⃣ Creating users with PBKDF2...");

  // Hash passwords for existing users
  const user1Hash = yield* pbkdf2Hasher.hash("oldpassword123");
  const user2Hash = yield* pbkdf2Hasher.hash("newpassword456");

  users.get("user1")!.passwordHash = user1Hash.hash;
  users.get("user2")!.passwordHash = user2Hash.hash;

  console.log(`   ✅ User1 hash (${user1Hash.algorithm}): ${user1Hash.hash.substring(0, 50)}...`);
  console.log(`   ✅ User2 hash (${user2Hash.algorithm}): ${user2Hash.hash.substring(0, 50)}...\n`);

  // Create a multi-algorithm verifier
  // In production, you might add Argon2, Bcrypt, etc.
  const verifier = Auth.makeMultiAlgorithmVerifier([
    pbkdf2Hasher,
    // Could add more: makeArgon2Hasher(), makeBcryptHasher(), etc.
  ]);

  console.log("2️⃣ Creating multi-algorithm verifier...");
  console.log("   Supported algorithms: PBKDF2-SHA256");
  console.log("   (In production, you could add Argon2, Bcrypt, etc.)\n");

  // Verify passwords using the multi-algorithm verifier
  console.log("3️⃣ Verifying user credentials...");

  // Simulate login for user1
  const user1 = users.get("user1")!;
  const user1Valid = yield* verifier.verify("oldpassword123", user1.passwordHash);
  console.log(`   ✅ User1 (${user1.email}): ${user1Valid ? "Valid" : "Invalid"}`);

  // Simulate login for user2
  const user2 = users.get("user2")!;
  const user2Valid = yield* verifier.verify("newpassword456", user2.passwordHash);
  console.log(`   ✅ User2 (${user2.email}): ${user2Valid ? "Valid" : "Invalid"}\n`);

  // Test wrong password
  console.log("4️⃣ Testing incorrect password...");
  const wrongPasswordValid = yield* verifier.verify("wrongpassword", user1.passwordHash);
  console.log(`   ✅ Wrong password correctly rejected: ${!wrongPasswordValid}\n`);

  // Demonstrate algorithm detection
  console.log("5️⃣ Automatic algorithm detection...");
  console.log("   The verifier automatically detects the algorithm from the PHC format:");
  console.log(`   User1 algorithm: ${user1.passwordHash.split("$")[0]}`);
  console.log(`   User2 algorithm: ${user2.passwordHash.split("$")[0]}\n`);

  // Demonstrate error handling for unsupported algorithm
  console.log("6️⃣ Testing unsupported algorithm...");
  const unsupportedResult = yield* Effect.either(
    verifier.verify("password", "argon2$someParams$hash"),
  );
  if (unsupportedResult._tag === "Left") {
    console.log(`   ✅ Unsupported algorithm correctly rejected:`);
    console.log(`      ${unsupportedResult.left.message}\n`);
  }

  console.log("✨ Multi-algorithm verification example completed!\n");

  console.log("💡 Benefits of this approach:");
  console.log("   • Seamless migration between algorithms");
  console.log("   • Support multiple algorithms in the same database");
  console.log("   • Upgrade security without breaking existing users");
  console.log("   • Trait-based design allows custom implementations");
  console.log("   • PHC format ensures interoperability\n");

  return {
    user1Valid,
    user2Valid,
    wrongPasswordValid,
  };
});

/**
 * Run the example
 */
const runExample = async () => {
  try {
    const result = await Effect.runPromise(
      Effect.provide(multiAlgorithmExample, Auth.PasswordHasherLive),
    );

    console.log("📊 Final Results:");
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error("❌ Error:", error);
    process.exit(1);
  }
};

// Run if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runExample();
}

export { multiAlgorithmExample };
