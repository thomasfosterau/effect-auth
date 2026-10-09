---
"@thomasfosterau/effect-auth": patch
---

Doc comments only: the `Ladder.make` and `Hooks` class examples now run under docgen. The `Ladder` example moved from the module comment (which docgen does not read) onto `make`, and the `Hooks.tap` example moved from the `static readonly` member (which docgen does not extract) onto the `Hooks` class. Both assert their results. The `.d.ts` changes are those doc comments.
