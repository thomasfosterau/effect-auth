/**
 * In-memory implementations of the storage interfaces required by effect-auth.
 *
 * Each adapter is backed by the maps defined in `./domain.ts`. In production
 * you would replace these with real persistence (Postgres, Redis, etc.).
 */

import { Effect } from "effect";
import * as Auth from "effect-auth";
import {
  type Employee,
  emailVerifications,
  employees,
  findEmployeeByEmail,
  nextId,
  oauthAccounts,
  oauthStates,
  passwords,
  rateLimits,
  sessions,
  userRoles,
} from "./domain.ts";
import { NorthwindRoles } from "./permissions.ts";

// ---------------------------------------------------------------------------
// SessionStore + UserStore (consumed by SessionManager)
// ---------------------------------------------------------------------------

export const sessionStore: Auth.SessionStore = {
  create: (session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),
  get: (sessionId) =>
    Effect.suspend(() => {
      const session = sessions.get(sessionId);
      return session
        ? Effect.succeed(session)
        : Effect.fail(
            new Auth.SessionNotFoundError({
              message: "Session not found",
              sessionId,
            }),
          );
    }),
  update: (session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),
  delete: (sessionId) =>
    Effect.sync(() => {
      sessions.delete(sessionId);
    }),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      for (const [id, session] of sessions) {
        if (session.userId === userId) sessions.delete(id);
      }
    }),
  listByUserId: (userId) =>
    Effect.sync(() => Array.from(sessions.values()).filter((session) => session.userId === userId)),
};

const employeeToUser = (employee: Employee): Auth.User => ({
  id: employee.id,
  email: employee.email,
  emailVerified: employee.emailVerified,
  name: `${employee.firstName} ${employee.lastName}`.trim(),
  createdAt: employee.createdAt,
  updatedAt: employee.updatedAt,
  attributes: { ...employee.attributes },
});

export const userStore: Auth.UserStore = {
  get: (userId) =>
    Effect.suspend(() => {
      const employee = employees.get(userId);
      return employee
        ? Effect.succeed(employeeToUser(employee))
        : Effect.fail(new Auth.UserNotFoundError({ message: "User not found", userId }));
    }),
  getCredentials: (userId) =>
    Effect.suspend(() => {
      const hash = passwords.get(userId);
      return hash
        ? Effect.succeed(hash)
        : Effect.fail(new Auth.UserNotFoundError({ message: "User not found", userId }));
    }),
};

// ---------------------------------------------------------------------------
// UserServiceStore (consumed by UserService)
// ---------------------------------------------------------------------------

const updateEmployeeFromUser = (user: Auth.User): Employee => {
  const existing = employees.get(user.id);
  if (!existing) {
    throw new Error(`Cannot update missing employee ${user.id}`);
  }
  const name = user.name;
  const updated: Employee = {
    ...existing,
    email: user.email.length > 0 ? user.email : existing.email,
    emailVerified: user.emailVerified,
    firstName:
      typeof name === "string" && name.length > 0
        ? (name.split(" ")[0] ?? existing.firstName)
        : existing.firstName,
    lastName:
      typeof name === "string" && name.split(" ").length > 1
        ? name.split(" ").slice(1).join(" ")
        : existing.lastName,
    updatedAt: user.updatedAt,
    attributes: { ...user.attributes },
  };
  employees.set(updated.id, updated);
  return updated;
};

export const userServiceStore: Auth.UserServiceStore = {
  get: (userId) =>
    Effect.suspend(() => {
      const employee = employees.get(userId);
      return employee
        ? Effect.succeed(employeeToUser(employee))
        : Effect.fail(new Auth.UserNotFoundError({ message: "User not found", userId }));
    }),
  getByEmail: (email) =>
    Effect.sync(() => {
      const employee = findEmployeeByEmail(email);
      return employee ? employeeToUser(employee) : null;
    }),
  update: (user) =>
    Effect.sync(() => {
      const updated = updateEmployeeFromUser(user);
      return employeeToUser(updated);
    }),
  delete: (userId) =>
    Effect.sync(() => {
      employees.delete(userId);
      passwords.delete(userId);
      userRoles.delete(userId);
    }),
};

// ---------------------------------------------------------------------------
// EmailPasswordStore (consumed by EmailPasswordService / AuthLifecycle)
// ---------------------------------------------------------------------------

export const emailPasswordStore: Auth.EmailPasswordStore = {
  getUserByEmail: (email) =>
    Effect.sync(() => {
      const employee = findEmployeeByEmail(email);
      return employee ? employeeToUser(employee) : null;
    }),
  createUser: (input) =>
    Effect.sync(() => {
      const id = nextId("emp");
      const name = input.name ?? input.email;
      const [firstName, ...rest] = name.split(" ");
      const now = new Date();
      const employee: Employee = {
        id,
        email: input.email,
        emailVerified: false,
        firstName: firstName ?? input.email,
        lastName: rest.join(" "),
        title: "Sales Representative",
        createdAt: now,
        updatedAt: now,
        attributes: { ...input.attributes },
      };
      employees.set(id, employee);
      // New sign-ups land in the SalesRep role by default; admins can promote.
      userRoles.set(id, [NorthwindRoles.SalesRep]);
      return employeeToUser(employee);
    }),
  getPasswordHash: (userId) => Effect.sync(() => passwords.get(userId) ?? null),
  setPasswordHash: (userId, hash) =>
    Effect.sync(() => {
      passwords.set(userId, hash);
    }),
};

// ---------------------------------------------------------------------------
// EmailVerificationStore
// ---------------------------------------------------------------------------

export const emailVerificationStore: Auth.EmailVerificationStore = {
  create: (verification) =>
    Effect.sync(() => {
      emailVerifications.set(verification.token, verification);
      return verification;
    }),
  get: (token) => Effect.sync(() => emailVerifications.get(token) ?? null),
  delete: (token) =>
    Effect.sync(() => {
      emailVerifications.delete(token);
    }),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      for (const [token, verification] of emailVerifications) {
        if (verification.userId === userId) emailVerifications.delete(token);
      }
    }),
};

// ---------------------------------------------------------------------------
// RateLimitStore
// ---------------------------------------------------------------------------

export const rateLimitStore: Auth.RateLimitStore = {
  get: (key) => Effect.succeed(rateLimits.get(key) ?? null),
  set: (key, entry, _ttl) =>
    Effect.sync(() => {
      rateLimits.set(key, entry);
    }),
  increment: (key, ttlSeconds) =>
    Effect.sync(() => {
      const now = Date.now();
      const existing = rateLimits.get(key);
      if (!existing || now >= existing.resetAt) {
        const fresh: Auth.RateLimitEntry = {
          key,
          count: 1,
          resetAt: now + ttlSeconds * 1000,
        };
        rateLimits.set(key, fresh);
        return 1;
      }
      const next: Auth.RateLimitEntry = { ...existing, count: existing.count + 1 };
      rateLimits.set(key, next);
      return next.count;
    }),
  delete: (key) =>
    Effect.sync(() => {
      rateLimits.delete(key);
    }),
};

// ---------------------------------------------------------------------------
// OAuth stores
// ---------------------------------------------------------------------------

export const oauthStateStore: Auth.OAuthStateStore = {
  create: (state) =>
    Effect.sync(() => {
      oauthStates.set(state.state, state);
      return state;
    }),
  get: (state) =>
    Effect.suspend(() => {
      const entry = oauthStates.get(state);
      return entry
        ? Effect.succeed(entry)
        : Effect.fail(new Auth.AuthError({ message: `OAuth state not found: ${state}` }));
    }),
  delete: (state) =>
    Effect.sync(() => {
      oauthStates.delete(state);
    }),
};

const accountKey = (provider: string, providerId: string): string => `${provider}:${providerId}`;

export const oauthAccountStore: Auth.OAuthAccountStore = {
  create: (account) =>
    Effect.sync(() => {
      oauthAccounts.set(accountKey(account.provider, account.providerId), account);
      return account;
    }),
  get: (provider, providerId) =>
    Effect.sync(() => oauthAccounts.get(accountKey(provider, providerId)) ?? null),
  getByUserId: (userId) =>
    Effect.sync(() =>
      Array.from(oauthAccounts.values()).filter((account) => account.userId === userId),
    ),
  update: (account) =>
    Effect.sync(() => {
      oauthAccounts.set(accountKey(account.provider, account.providerId), account);
      return account;
    }),
  linkToUser: (userId, account) =>
    Effect.sync(() => {
      oauthAccounts.set(accountKey(account.provider, account.providerId), {
        ...account,
        userId,
      });
    }),
  unlinkFromUser: (userId, provider) =>
    Effect.sync(() => {
      for (const [key, account] of oauthAccounts) {
        if (account.userId === userId && account.provider === provider) {
          oauthAccounts.delete(key);
        }
      }
    }),
  delete: (provider, providerId) =>
    Effect.sync(() => {
      oauthAccounts.delete(accountKey(provider, providerId));
    }),
};
