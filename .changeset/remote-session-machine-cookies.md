---
"@thomasfosterau/effect-auth": patch
---

`Http.RemoteSession`'s `read`, and `resolveAtEdge` through it, no longer hand `Set-Cookie` lines to a caller carrying an API key or a bearer token, matching `relay`. Every `credentials.apiKeyHeaders` name is now forwarded on every call, so a key header can no longer be forwarded without counting as a machine credential.
