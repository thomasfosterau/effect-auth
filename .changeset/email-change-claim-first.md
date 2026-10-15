---
"@thomasfosterau/effect-auth": patch
---

Email change claims the new address first and releases the previous address after the claim succeeds. A failed claim, whether another account took the address or the identifier store failed, leaves the user's previous address in place and verified, and the confirm token is not consumed (#364).
