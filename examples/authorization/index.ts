/**
 * Authorization example with role-based access control
 *
 * This example demonstrates:
 * - Building a RoleStore with `makeInMemoryRoleStore` (no hand-rolled Maps)
 * - Role inheritance (editor inherits viewer) and wildcard permissions (admin → *:*)
 * - Checking and requiring permissions
 * - Composing policies with combinators (allOf / anyOf)
 * - Batch guards (requireAllPermissions)
 * - OAuth-style scope checks (hasScope / requireScope)
 */

import { Effect, Layer } from "effect";
import * as Auth from "effect-auth";

// Permissions granted directly by each role. `admin` uses a "*:*" wildcard to
// grant everything; `editor` inherits `viewer` via the role hierarchy below.
const rolePermissions = {
  admin: [{ resource: "*", action: "*" }],
  editor: [
    { resource: "posts", action: "create" },
    { resource: "posts", action: "update" },
    { resource: "posts", action: "delete" },
  ],
  viewer: [
    { resource: "posts", action: "read" },
    { resource: "users", action: "read" },
  ],
};

// editor inherits all of viewer's permissions.
const roleHierarchy = {
  editor: ["viewer"],
};

// User role assignments.
const userRoles = {
  "user-1": ["admin"],
  "user-2": ["editor"],
  "user-3": ["viewer"],
};

/**
 * Build an in-memory RoleStore and a role-based AuthorizationPolicy from it.
 */
const roleStore = Auth.makeInMemoryRoleStore({ userRoles, rolePermissions, roleHierarchy });

const RoleStoreLayer = Layer.succeed(Auth.RoleStore, roleStore);
const AppLayer = Layer.merge(
  RoleStoreLayer,
  Layer.effect(Auth.AuthorizationPolicy, Auth.makeRoleBasedPolicy()).pipe(
    Layer.provide(RoleStoreLayer),
  ),
);

/**
 * Authorization flow example
 */
const authorizationFlow = Effect.gen(function* () {
  console.log("🔐 Starting authorization example...\n");

  const policy = yield* Auth.makeRoleBasedPolicy();

  // Test 1: Admin has wildcard permissions
  console.log("1️⃣ Admin (wildcard *:*) permissions...");
  const adminCanDelete = yield* policy.checkPermission("user-1", "users", "delete");
  const adminCanDoAnything = yield* policy.checkPermission("user-1", "anything", "destroy");
  console.log(`   Admin can delete users: ${adminCanDelete}`);
  console.log(`   Admin can destroy anything: ${adminCanDoAnything}\n`);

  // Test 2: Editor inherits viewer's read permission
  console.log("2️⃣ Editor (inherits viewer) permissions...");
  const editorCanCreate = yield* policy.checkPermission("user-2", "posts", "create");
  const editorCanRead = yield* policy.checkPermission("user-2", "posts", "read"); // inherited
  const editorCanDeleteUser = yield* policy.checkPermission("user-2", "users", "delete");
  console.log(`   Editor can create posts: ${editorCanCreate}`);
  console.log(`   Editor can read posts (inherited): ${editorCanRead}`);
  console.log(`   Editor can delete users: ${editorCanDeleteUser}\n`);

  // Test 3: requireAllPermissions guard
  console.log("3️⃣ Requiring multiple permissions at once...");
  yield* Auth.requireAllPermissions("user-2", [
    { resource: "posts", action: "create" },
    { resource: "posts", action: "read" },
  ]);
  console.log("   ✅ Editor has both create and read on posts\n");

  // Test 4: requirePermission failure
  console.log("4️⃣ Requiring a permission the viewer lacks...");
  const denied = yield* Effect.either(Auth.requirePermission("user-3", "posts", "delete"));
  if (denied._tag === "Left") {
    console.log(`   ❌ Permission denied: ${denied.left.message}\n`);
  }

  return { adminCanDelete, adminCanDoAnything, editorCanCreate, editorCanRead };
});

/**
 * Policy combinator example: a post can be edited if the user has the editor
 * permission OR is the author of the post (an ABAC-style ownership rule).
 */
const combinatorExample = Effect.gen(function* () {
  console.log("=".repeat(50));
  console.log("🧩 Policy Combinators (RBAC + ABAC)");
  console.log("=".repeat(50) + "\n");

  const rbac = yield* Auth.makeRoleBasedPolicy();

  // Ownership rule: user-3 happens to own the post they are editing.
  const isAuthor = Auth.fromPredicate((userId, resource) =>
    Effect.succeed(resource === "posts" && userId === "user-3"),
  );

  const canEditPost = Auth.anyOf(rbac, isAuthor);

  const editorAllowed = yield* canEditPost.checkPermission("user-2", "posts", "update");
  const authorAllowed = yield* canEditPost.checkPermission("user-3", "posts", "update");
  const strangerAllowed = yield* canEditPost.checkPermission("user-99", "posts", "update");

  console.log(`   Editor can update via role:  ${editorAllowed}`);
  console.log(`   Author can update via ownership: ${authorAllowed}`);
  console.log(`   Stranger can update: ${strangerAllowed}\n`);

  return { editorAllowed, authorAllowed, strangerAllowed };
});

/**
 * OAuth-style scope example.
 */
const scopeExample = Effect.gen(function* () {
  console.log("=".repeat(50));
  console.log("🎫 OAuth Scope Checks");
  console.log("=".repeat(50) + "\n");

  const token = "read:user write:repo";

  console.log(`   Granted scopes: "${token}"`);
  console.log(`   hasScope write:repo -> ${Auth.hasScope(token, "write:repo")}`);
  console.log(`   hasScope delete:repo -> ${Auth.hasScope(token, "delete:repo")}`);

  yield* Auth.requireScope(token, "read:user");
  console.log("   ✅ requireScope read:user passed");

  const denied = yield* Effect.either(Auth.requireScope(token, "admin:org"));
  if (denied._tag === "Left") {
    console.log(`   ❌ ${denied.left.message}\n`);
  }

  return { ok: true };
});

/**
 * Run the examples
 */
const runExamples = async () => {
  try {
    const authResult = await Effect.runPromise(Effect.provide(authorizationFlow, AppLayer));
    console.log("📊 Authorization Test Results:");
    console.log(JSON.stringify(authResult, null, 2) + "\n");

    const comboResult = await Effect.runPromise(Effect.provide(combinatorExample, AppLayer));
    console.log("📊 Combinator Results:");
    console.log(JSON.stringify(comboResult, null, 2) + "\n");

    await Effect.runPromise(scopeExample);

    console.log("\n✨ Authorization example completed successfully!");
  } catch (error) {
    console.error("❌ Error:", error);
    process.exit(1);
  }
};

// Run if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runExamples();
}

export { authorizationFlow, combinatorExample, scopeExample, roleStore };
