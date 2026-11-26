---
"@thomasfosterau/effect-auth": minor
---

`OAuthAccountStore.create` is a plain insert: a provider account already linked is refused, and `OAuthService` re-reads it and fails with `OAuthAccountConflictError` (now also in `handleCallback`'s and `signInWithCallback`'s error channels), so two concurrent first sign-ins with one provider account no longer both win and a link no longer moves silently to another user. `update` is keyed on `id`, refreshes only the tokens and profile fields, never changes `userId` and never creates a link; it returns the stored link, or `null` when none has that id. `linkToUser` updates an existing link only. The `./sql` store and `Testing.memoryOAuthAccountStore` follow, `Testing.oauthAccountStoreConformance` gains a duplicate-link case and an update case, and `docs/guides/byo-stores.md` no longer recommends an upsert. A custom store that upserts in `create` or `update` must change.

`SessionStore.update` must never create a session: a session signed out or revoked between a read and its write stays gone. `Testing.memorySessionStore`, the README's map store and the JSDoc examples now update only a stored session, and `Testing.sessionStoreConformance` gains a case for it.
