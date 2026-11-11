---
"@thomasfosterau/effect-auth": patch
"@thomasfosterau/effect-auth-alchemy-postgres": patch
"@thomasfosterau/effect-auth-drizzle": patch
"@thomasfosterau/effect-auth-resend": patch
"@thomasfosterau/effect-auth-twilio": patch
---

Drop redundant default type arguments from the published declarations (`Redacted.Redacted<string>` is now written `Redacted.Redacted`, `Effect.Effect<A, E, never>` is `Effect.Effect<A, E>`, and so on); every type is unchanged (#503). Values that were stringified with `String(…)` are now converted explicitly: an OAuth profile id that is neither a string nor a number becomes `""` rather than `"[object Object]"`, the unsupported `id_token` algorithm error formats the header value (`"HS256"`), and a Twilio error body whose `code` or `message` is not a string is rendered as JSON.
