/**
 * Authorization example with role-based access control
 *
 * This example demonstrates:
 * - Implementing a role store
 * - Setting up role-based authorization
 * - Checking permissions
 * - Using requirePermission helper
 */

import { Effect, Context } from "effect";
import * as Auth from "effect-auth";

// Define roles and permissions
const rolePermissions = new Map([
  [
    "admin",
    [
      { resource: "posts", action: "create" },
      { resource: "posts", action: "read" },
      { resource: "posts", action: "update" },
      { resource: "posts", action: "delete" },
      { resource: "users", action: "create" },
      { resource: "users", action: "read" },
      { resource: "users", action: "update" },
      { resource: "users", action: "delete" },
    ],
  ],
  [
    "editor",
    [
      { resource: "posts", action: "create" },
      { resource: "posts", action: "read" },
      { resource: "posts", action: "update" },
      { resource: "posts", action: "delete" },
    ],
  ],
  [
    "viewer",
    [
      { resource: "posts", action: "read" },
      { resource: "users", action: "read" },
    ],
  ],
]);

// User role assignments
const userRoles = new Map([
  ["user-1", ["admin"]],
  ["user-2", ["editor"]],
  ["user-3", ["viewer"]],
  ["user-4", ["editor", "viewer"]],
]);

/**
 * Implement RoleStore
 */
const roleStore: Auth.RoleStore = {
  getUserRoles: (userId) =>
    Effect.sync(() => {
      const roles = userRoles.get(userId);
      return roles || [];
    }),

  getRolePermissions: (role) =>
    Effect.sync(() => {
      const permissions = rolePermissions.get(role);
      return permissions || [];
    }),
};

/**
 * Authorization flow example
 */
const authorizationFlow = Effect.gen(function* () {
  console.log("🔐 Starting authorization example...\n");

  // Create role-based policy
  const policy = yield* Auth.makeRoleBasedPolicy();

  // Test 1: Admin permissions
  console.log("1️⃣ Testing admin permissions...");
  const adminCanDelete = yield* policy.checkPermission("user-1", "users", "delete");
  console.log(`   Admin can delete users: ${adminCanDelete}\n`);

  // Test 2: Editor permissions
  console.log("2️⃣ Testing editor permissions...");
  const editorCanCreatePost = yield* policy.checkPermission("user-2", "posts", "create");
  const editorCanDeleteUser = yield* policy.checkPermission("user-2", "users", "delete");
  console.log(`   Editor can create posts: ${editorCanCreatePost}`);
  console.log(`   Editor can delete users: ${editorCanDeleteUser}\n`);

  // Test 3: Viewer permissions
  console.log("3️⃣ Testing viewer permissions...");
  const viewerCanRead = yield* policy.checkPermission("user-3", "posts", "read");
  const viewerCanUpdate = yield* policy.checkPermission("user-3", "posts", "update");
  console.log(`   Viewer can read posts: ${viewerCanRead}`);
  console.log(`   Viewer can update posts: ${viewerCanUpdate}\n`);

  // Test 4: Using requirePermission (will succeed)
  console.log("4️⃣ Using requirePermission for valid permission...");
  yield* Auth.requirePermission("user-1", "posts", "create");
  console.log("   ✅ Admin has permission to create posts\n");

  // Test 5: Using requirePermission (will fail)
  console.log("5️⃣ Using requirePermission for invalid permission...");
  const result = yield* Effect.either(Auth.requirePermission("user-3", "posts", "delete"));
  if (result._tag === "Left") {
    console.log(`   ❌ Permission denied: ${result.left.message}\n`);
  }

  // Test 6: User with multiple roles
  console.log("6️⃣ Testing user with multiple roles...");
  const multiRoleCanCreate = yield* policy.checkPermission("user-4", "posts", "create");
  const multiRoleCanRead = yield* policy.checkPermission("user-4", "posts", "read");
  console.log(`   User-4 can create posts: ${multiRoleCanCreate}`);
  console.log(`   User-4 can read posts: ${multiRoleCanRead}\n`);

  console.log("✨ Authorization example completed successfully!");

  return {
    tests: {
      adminCanDelete,
      editorCanCreatePost,
      editorCanDeleteUser,
      viewerCanRead,
      viewerCanUpdate,
      multiRoleCanCreate,
      multiRoleCanRead,
    },
  };
});

/**
 * Simulate a protected operation
 */
const createPost = (userId: string, title: string, content: string) =>
  Effect.gen(function* () {
    // Check permission first
    yield* Auth.requirePermission(userId, "posts", "create");

    // If we get here, permission was granted
    const post = {
      id: Math.random().toString(36).substring(7),
      title,
      content,
      authorId: userId,
      createdAt: new Date(),
    };

    console.log(`📝 Post created by ${userId}:`);
    console.log(`   Title: ${title}`);
    console.log(`   ID: ${post.id}`);

    return post;
  });

/**
 * Example of protecting operations
 */
const protectedOperationsExample = Effect.gen(function* () {
  console.log("\n" + "=".repeat(50));
  console.log("🛡️  Protected Operations Example");
  console.log("=".repeat(50) + "\n");

  // Admin creates a post (should succeed)
  console.log("1️⃣ Admin creating post...");
  const adminPost = yield* createPost("user-1", "Admin Post", "Content by admin");
  console.log("   ✅ Success!\n");

  // Editor creates a post (should succeed)
  console.log("2️⃣ Editor creating post...");
  const editorPost = yield* createPost("user-2", "Editor Post", "Content by editor");
  console.log("   ✅ Success!\n");

  // Viewer tries to create a post (should fail)
  console.log("3️⃣ Viewer attempting to create post...");
  const viewerResult = yield* Effect.either(
    createPost("user-3", "Viewer Post", "This should fail"),
  );
  if (viewerResult._tag === "Left") {
    console.log(`   ❌ Denied: ${viewerResult.left.message}\n`);
  }

  console.log("✨ Protected operations example completed!");

  return {
    adminPost,
    editorPost,
    viewerDenied: viewerResult._tag === "Left",
  };
});

/**
 * Run the examples
 */
const runExamples = async () => {
  try {
    // Run authorization flow
    const authResult = await Effect.runPromise(
      Effect.provide(authorizationFlow, Context.make(Auth.RoleStore, roleStore)),
    );

    console.log("\n📊 Authorization Test Results:");
    console.log(JSON.stringify(authResult, null, 2));

    // Run protected operations example
    const opsResult = await Effect.runPromise(
      Effect.provide(protectedOperationsExample, Context.make(Auth.RoleStore, roleStore)),
    );

    console.log("\n📊 Protected Operations Results:");
    console.log(JSON.stringify(opsResult, null, 2));
  } catch (error) {
    console.error("❌ Error:", error);
    process.exit(1);
  }
};

// Run if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runExamples();
}

export { authorizationFlow, protectedOperationsExample, roleStore };
