---
"@thomasfosterau/effect-auth": minor
---

**Breaking:** options objects spell an optional member `readonly x?: T`, without `| undefined`. Under `exactOptionalPropertyTypes`, a caller that holds a value that may be `undefined` leaves the key out, for example with `...(x !== undefined && { x })`, instead of passing `x: undefined`. This covers every service `layer(...)` config, the sign-in and send inputs, the hook attempts and the HTTP handler options.

Also breaking:

- `ProfileMap.str` returns `Option<string>`, and `ProfileMap.profile` takes `email`, `name` and `picture` as `Option<string>`, so a custom `mapProfile` passes `str(...)` results straight through.
- `RootSecret.Encryption` no longer includes `undefined`; `sealerFor` takes it as an optional parameter.
