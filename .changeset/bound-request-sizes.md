---
"@thomasfosterau/effect-auth": minor
---

Bound every request: `Http.make` now counts body bytes as they stream in and answers `413` once they pass `maxBodySize`, even without a `Content-Length`. Identifier, name, token and URL fields take at most `MAX_IDENTIFIER_LENGTH` (320), `MAX_NAME_LENGTH` (256), `MAX_TOKEN_LENGTH` (4096) and `MAX_URL_LENGTH` (2048) characters, and attribute and metadata bags at most `MAX_ATTRIBUTES_BYTES` (8192) bytes as JSON (constants exported from `/http`); a larger write is refused with `400`, while stored values of any size are still answered. The multi-session device cookie is read as at most `maximumSessions` ids, and the base32 and WebAuthn base64url decoders run in linear time and memory.
