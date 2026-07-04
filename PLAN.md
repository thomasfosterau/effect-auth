# Surrogate-Keyed Identity Model — Remaining Phases

Epic goal: make `User` require no natural key; email, username, and phone become
first-class `Identifier`s with global uniqueness on `(type, value)`.

Phase 1 (this PR) laid the foundations:

- `Identifier` domain type and `IdentifierStore` contract in `Identifier.ts`
- KeyValueStore-backed and `@effect-auth/sql` implementations
- `auth_identifiers` SQL table/migration
- `primaryEmail` / `primaryEmailValue` helpers and `UserWithIdentifiers` read view
- Tests for the KV store and helpers

---

## Phase 2 — Make `User` surrogate-keyed

**Goal:** Remove `email` and `emailVerified` from `User` (or mark them optional /
deprecated) so the record requires no natural key. `User` becomes purely:
`{ id, name?, image?, createdAt, updatedAt, attributes }`.

**Steps:**

1. Update `Types.ts`: remove `email: Schema.String` and `emailVerified: Schema.Boolean`
   from the `User` schema (or make them `Schema.optional` with a deprecation comment
   during a transition window).
2. Update `UserStoreShape` / `UserServiceStoreShape` in `User.ts`: remove `getByEmail`,
   `getUserByEmail` (callers must now query `IdentifierStore.getByValue("email", ...)` to
   resolve a user id, then fetch the user by id).
3. Update `@effect-auth/sql` `auth_users` DDL: remove `email` and `email_verified` columns
   (behind a migration step for existing deployments).
4. Update `@effect-auth/sql` `Stores.ts`: remove `email`/`email_verified` columns from
   inserts/selects; drop the `auth_users_email_idx` unique index.
5. Update `@effect-auth/alchemy` in parallel.
6. Add a `DESIGN.md` decision entry for this breaking change.

**Blast radius:** large — every module that reads/writes `user.email` directly.
Stage behind a Changeset (major for `effect-auth`, major for sql/alchemy).

---

## Phase 3 — Migrate EmailPassword flow

**Goal:** Replace the `getUserByEmail` lookup in `EmailPassword.ts` with an
`IdentifierStore` lookup.

**Steps:**

1. Remove `getUserByEmail` from `EmailPasswordStoreShape`.
2. In `makeEmailPasswordService`, replace:
   ```ts
   store.getUserByEmail(normalizeEmail(email));
   ```
   with:
   ```ts
   identifierStore
     .getByValue("email", normalizeEmail(email))
     .flatMap((id) => (id ? userStore.get(id.userId) : Effect.succeed(null)));
   ```
3. Sign-up: after creating the user, call `identifierStore.create(...)` to record
   the email identifier (verified=false initially).
4. Update `EmailPasswordStore` — remove `getUserByEmail` from the interface
   (implementors only need `createUser`, `getPasswordHash`, `setPasswordHash`).
5. Tests: update `EmailPassword.test.ts`.

---

## Phase 4 — Migrate Username flow

**Goal:** Replace `UsernameStore.getUserByUsername` with an `IdentifierStore` lookup.

**Steps:**

1. Replace `getUserByUsername` / `isUsernameTaken` / `setUsername` in `UsernameStoreShape`
   with a simpler shape (or remove the store entirely — `IdentifierStore` subsumes it).
2. Sign-up: create a `username` identifier in `IdentifierStore` after creating the user.
3. Sign-in: `identifierStore.getByValue("username", normalized)` → userId → user.
4. Update `Username.ts` to depend on `IdentifierStore` instead of `UsernameStore`.

---

## Phase 5 — Migrate PhoneOtp flow

**Goal:** Replace phone lookups in `PhoneOtp.ts` with `IdentifierStore`.

**Steps:**

1. Phone verification now marks the `phone` identifier as verified via
   `IdentifierStore.setVerified`.
2. Sign-in: `identifierStore.getByValue("phone", normalized)` → userId.
3. Remove `attributes.phoneNumber` / `attributes.phoneNumberVerified` conventions
   once the identifier is the canonical source of truth.

---

## Phase 6 — Email-change and email-verification flows

**Goal:** Route `AccountManagement.changeEmail` and `EmailVerification` through
`IdentifierStore` instead of `user.email`.

**Steps:**

1. `EmailVerification`: on success call `identifierStore.setVerified(id, now)` instead
   of `userService.markEmailVerified`.
2. `AccountManagement.changeEmail`: create a new `email` identifier (unverified), send
   the verification token for it, and on confirm delete the old identifier (or mark it
   as primary=false if multi-email is supported).
3. Remove `markEmailVerified` from `UserServiceShape` if it is no longer needed.

---

## Phase 7 — HTTP schema changes

**Goal:** Update the HTTP contract to reflect the identifier model.

**Steps:**

1. Remove `email` / `emailVerified` from the `UserResponse` schema in
   `HttpApiSchemas.ts` (or expose them via the `UserWithIdentifiers` read view).
2. Add `GET /identifiers` endpoint to list a user's identifiers.
3. Add `DELETE /identifiers/:id` endpoint.
4. Update `signUp` request bodies that currently include an `email` field to
   instead record the email through `IdentifierStore` internally.
5. Update the generated `HttpClient` and `@effect-auth/client`.

---

## Phase 8 — Data migration guide

**Goal:** Document how existing deployments migrate from `user.email` to
`auth_identifiers`.

**Steps:**

1. Write a migration script that reads every row from `auth_users` and inserts a
   corresponding row into `auth_identifiers` (`type="email"`, `value=email`,
   `verified=email_verified`, `created_at=user.created_at`).
2. Document the script in `CONTRIBUTING.md` under "Upgrading from 0.x".
3. Add a `DESIGN.md` decision entry for the identifier model (D12 or similar).

---

## Cross-cutting concerns (all phases)

- Keep a Changeset for each phase; phases 2–8 are all breaking and should land in
  one coordinated 1.0 release or as a staged pre-release series.
- `@effect-auth/alchemy` must be updated in lockstep with `@effect-auth/sql` for
  every schema change.
- The `WorkOS` package must check whether its user model is affected.
- All 13 examples need to be updated to the new API before 1.0.
