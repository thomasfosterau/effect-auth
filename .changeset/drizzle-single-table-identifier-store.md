---
"@thomasfosterau/effect-auth-drizzle": minor
---

Initial release of `SingleTableIdentifierStore`, an opt-in `IdentifierStore` that keeps a user's email identifier on the application's own `users` row: the address in `email`, its verified flag in `email_verified`, and the row's `created_at` as the identifier's creation time. An application whose users table already holds the login address can use it without an identifiers table. It holds one identifier per user, an email. Any other identifier type, and a second address for the same user, are refused with an `AuthError`. Enter through `SingleTableIdentifierStore.layer(SingleTableIdentifierStore.defineUsers({ ... }))`. The default multi-identifier `IdentifierStore` is the one `layer()` provides and stays the default.
