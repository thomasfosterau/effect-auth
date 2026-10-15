---
"@thomasfosterau/effect-auth": minor
---

`IdentifierStore.replace(from, to)` swaps one of a user's identifiers for a new value: it claims `to` and releases `from` as one change, so the user is never left holding neither. A store with transactions writes both at once; a store without them claims `to` before it releases `from`. It resolves to the replacement, or `null` when `from` is no longer the user's, and fails with `AuthError` when another user holds `to`'s value, as `create` does. `replace` is a required member of the contract, so a custom `IdentifierStore` implements it (see `docs/guides/byo-stores.md`). `memoryIdentifierStore` and `IdentifierStoreKV` implement it, and `replaceInputError` gives an implementation the shared refusal for a `to` with another user, another type or the same value.

`replaceIdentifier(store, from, to)` calls it with readable failures: `IdentifierTakenError` when another user holds the value, `IdentifierNotFoundError` when `from` is no longer the user's, `AuthError` for other store failures.

`AccountManagement.confirmEmailChange` changes the user's email of record through `replaceIdentifier`, then releases any other email the user holds; a user with no email claims the new one. It works on every identifier store, including one that holds a single email per user (#381).
