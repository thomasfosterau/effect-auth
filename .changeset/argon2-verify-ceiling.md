---
"@thomasfosterau/effect-auth-argon2": minor
---

Bound the costs `verify` will run for a stored hash (#752, security). This is a breaking change on 0.x: some stored hashes that verified before are now refused, the constructors can throw, and there are new exports.

`verify` read `m`, `t` and `p` from the stored PHC string and ran any positive value, so a corrupt or attacker-written hash (through a store-level compromise or a bring-your-own store bug) could demand gigabytes of memory or billions of iterations on the next sign-in; since the wasm memory is kept for the isolate's life, on Workers that killed the isolate for every request it served. `verify` now refuses, with a `HashingError` and before the kernel runs:

- a stored hash over a ceiling set by three new options: `maxMemoryKiB` (default `131072`, 128 MiB), `maxIterations` (default `10`) and `maxParallelism` (default `8`), named as in `@thomasfosterau/argon2`'s `verify`. The defaults sit above `serverProfile`, so every hash this package writes verifies; a hash written elsewhere with higher costs needs the ceiling raised;
- a stored hash whose parameter segment repeats a name or carries one other than `m`, `t` and `p` (`m=4294967295,m=256` used to read as `m=256`), so the ceiling always judges the costs the kernel would run;
- a stored hash longer than 512 characters, before it is copied into wasm memory (an honest one is at most about 210).

`argon2Hasher` and `argon2HasherLayer` now throw a `RangeError` when a cost (`memoryCost`, `timeCost`, `parallelism`) or a limit is not a positive integer, or when the configured costs exceed the ceiling, since that hasher would write hashes it refuses to verify; raise the ceiling with the costs. New exports: `Argon2VerifyLimits`, `defaultVerifyLimits`, `resolveVerifyLimits`.
