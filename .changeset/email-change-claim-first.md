---
"@thomasfosterau/effect-auth": patch
---

Email change claims the new address first and releases the previous address after the claim succeeds. A failed claim, whether another account took the address or the identifier store failed, leaves the user's previous address in place and verified, and the confirm token is not consumed (#364). An identifier store that holds one email per user refuses the claim, so the change fails with an `AuthError` and the previous address stays.
