---
"@thomasfosterau/effect-auth": minor
---

New `safeRedirect(target, fallback)` (#200): follow a client-supplied post-authentication redirect only when it is a same-origin path. Absolute and protocol-relative URLs, backslash forms, schemes, control characters and a missing target all fall back.
