# Northwind Traders — effect-auth example

A small, runnable Effect application that models the classic Northwind Traders
sample (employees, customers, products, categories, orders) and uses
`effect-auth` for sign-up, email verification, sign-in, session validation,
role-based authorization, login rate-limiting, and OAuth URL generation.

The example is intentionally self-contained: every store is an in-memory `Map`,
and OAuth credentials are placeholders (only the authorization-URL step is
exercised — token exchange is left as a comment).

## Run

From the repo root:

```bash
bun --filter @effect-auth-examples/northwind-traders start
```

Or from this directory:

```bash
bun run main.ts
```

The scenario prints a banner for each step and narrates the result.

## Files

| File             | Purpose                                                                                                                    |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `domain.ts`      | Northwind types, in-memory maps, and `seedNorthwind()` initializer.                                                        |
| `permissions.ts` | Roles, role → permission map, and the `RoleStore` implementation.                                                          |
| `adapters.ts`    | In-memory implementations of every `effect-auth` storage interface.                                                        |
| `northwind.ts`   | Permission-gated domain service (`listProducts`, `createCustomer`, `placeOrder`, `discontinueProduct`, `viewSalesReport`). |
| `layers.ts`      | Composes adapters + auth services into a single `AppLayer`.                                                                |
| `main.ts`        | End-to-end narrated scenario.                                                                                              |

## Roles & permissions

| Role               | product | customer     | order        | report |
| ------------------ | ------- | ------------ | ------------ | ------ |
| `SalesRep`         | read    | create, read | create, read | —      |
| `SalesManager`     | read    | \*           | \*           | read   |
| `InventoryManager` | \*      | read         | read         | —      |
| `Admin`            | \*      | \*           | \*           | \*     |

New sign-ups land in `SalesRep` by default (see `adapters.ts:createUser`); the
seeded admin is in `Admin`.

## Scenario

1. **Seed Northwind** — populate the admin employee, two categories, and three
   products. Hash and store the admin's password.
2. **Sign-up a Sales Rep** — `AuthLifecycleService.signUp` creates the user and
   sends a verification email; the demo's `sendEmail` callback captures the
   token into memory instead of mailing it.
3. **Verify email** — the captured token is replayed through
   `lifecycle.verifyEmail`, which marks the email verified and auto-issues a
   session.
4. **Validate the session** — `SessionManager.validateSession` returns the user
   plus a sliding-window expiry.
5. **Trip the rate limiter** — six failed sign-ins are wrapped in
   `RateLimiter.consumeToken` with `RateLimitPresets.login` (5/15min); the 6th
   attempt raises `RateLimitError`.
6. **SalesRep places an order** — `northwind.placeOrder` succeeds because
   `SalesRep` has `order:create`.
7. **SalesRep tries to discontinue a product** — denied; `SalesRep` lacks
   `product:update`.
8. **Admin discontinues the product** — `Admin` has full access.
9. **OAuth authorization URL** — `OAuthService.generateAuthorizationUrl`
   builds a GitHub URL and persists the state for callback verification.
10. **Sign out** — `SessionManager.invalidateSession` removes the session;
    a subsequent `validateSession` fails with `SessionNotFoundError`.

## Notes

- Storage is in-memory — restart the process and you lose everything.
- The OAuth callback (`handleCallback`) makes real HTTP calls to the provider
  and is not exercised here. To extend the example, set `GITHUB_CLIENT_ID` and
  `GITHUB_CLIENT_SECRET`, then wire up an HTTP route that invokes
  `oauth.handleCallback(state, code)`.
- Rate-limiting is applied at the call site by wrapping `lifecycle.signIn`;
  `AuthLifecycleService` does not rate-limit internally.
