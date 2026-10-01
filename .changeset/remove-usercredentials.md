---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-sql": minor
"@thomasfosterau/effect-auth-drizzle": minor
---

`UserStore` holds no credentials: its contract is `get` alone. Sign-in reads and
writes the password hash through
`Auth.Email.EmailPasswordStore.getPasswordHash`/`setPasswordHash`, which
`@thomasfosterau/effect-auth-sql` and `@thomasfosterau/effect-auth-drizzle`
implement. In `@thomasfosterau/effect-auth-drizzle`, `Requests.getUser` /
`UserStore.GetUser` batch user reads.
