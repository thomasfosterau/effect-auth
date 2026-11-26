---
"@thomasfosterau/effect-auth": patch
---

The `Guard` errors (`Unauthorized`, `Forbidden`) and the HTTP-boundary error classes in `./http` (`Conflict`, `BadRequest`, `NotFound`, `TooManyRequests`, `InternalServerError`, `OAuthError`, `OAuthInvalidClient` and the five `Scim*` errors) now carry a type brand, so TypeScript no longer accepts a structurally similar value where one of them is expected.
