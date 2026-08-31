---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-sql": minor
"@thomasfosterau/effect-auth-drizzle": minor
---

BREAKING: Remove `UserStore.getCredentials`. No core feature ever read password
hashes through it — sign-in reads and writes the hash through
`Auth.Email.EmailPasswordStore.getPasswordHash`/`setPasswordHash` instead — so
the method is dropped from the `UserStore` contract along with its
implementations in `@thomasfosterau/effect-auth-sql` and
`@thomasfosterau/effect-auth-drizzle`. `@thomasfosterau/effect-auth-drizzle`
also drops the `UserStore.GetUserCredentials` request and
`Requests.getUserCredentials` constructor; `Requests.getUser`/`UserStore.GetUser`
keep the same batched-resolver pattern.
