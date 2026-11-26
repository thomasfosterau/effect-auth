# Argon2id on Workers

The detail of `@thomasfosterau/effect-auth-argon2`: using the hasher directly, cost profiles, Workers, verify limits, rehashing and migration. Install it as its [README](https://github.com/thomasfosterau/effect-auth/blob/trunk/packages/argon2/README.md) shows.

## The hasher on its own

Or use the hasher directly:

```ts
import { Effect } from "effect";
import { argon2Hasher } from "@thomasfosterau/effect-auth-argon2/Argon2";

const hasher = argon2Hasher();

const program = Effect.gen(function* () {
  const { hash } = yield* hasher.hash("correct horse battery staple");
  return yield* hasher.verify("correct horse battery staple", hash);
});
```

## Cost profiles

`argon2Hasher()` defaults to OWASP's **low-memory** Argon2id profile so the defaults are safe on every runtime this package supports, Cloudflare Workers included:

| Profile          | `memoryCost`     | `timeCost` | `parallelism` | Use for                          |
| ---------------- | ---------------- | ---------- | ------------- | -------------------------------- |
| `defaultProfile` | `19456` (19 MiB) | `2`        | `1`           | Workers / constrained runtimes   |
| `serverProfile`  | `65536` (64 MiB) | `3`        | `1`           | Plain Node servers with headroom |

```ts
import { argon2HasherLayer } from "@thomasfosterau/effect-auth-argon2/Argon2";
import { serverProfile } from "@thomasfosterau/effect-auth-argon2/Common";

const layer = argon2HasherLayer(serverProfile);
// or tune individual parameters
const custom = argon2HasherLayer({ memoryCost: 32768, timeCost: 3 });
```

`serverProfile` costs roughly 5× the work of the default; measure it against your own latency budget before adopting it. Do **not** use it on Cloudflare Workers — a Workers isolate has a 128 MiB memory limit, and Argon2 allocates `memoryCost` KiB for the duration of each hash.

## Cloudflare Workers

workerd refuses to compile WebAssembly while it serves a request (`CompileError: WebAssembly.compile(): Wasm code generation disallowed by embedder`). Releases up to 0.1.3 used [`hash-wasm`](https://github.com/Daninet/hash-wasm), which compiles lazily on the first hash, so every sign-up and sign-in failed on a deployed Worker. The hasher now compiles its wasm once, at module scope, while the Worker starts; inside a request it only runs it. A test serves the hasher from the real `workerd` binary and hashes and verifies inside `fetch`.

What a Worker needs:

- **A compatibility date of 2025-06-01 or later**, or the `allow_eval_during_startup` compatibility flag on an older date. Before that date workerd refuses wasm compilation at startup as well, and the Worker fails to start with the same `CompileError`.
- **`nodejs_compat`** on a compatibility date before 2026-08-04 (it is the default from that date). This package needs no `node:` module, but `@thomasfosterau/effect-auth`'s root imports `node:crypto`.
- **No bundler configuration.** The wasm is a base64 string in this package's JavaScript, not a `.wasm` import, so Wrangler, Vite (with or without `@cloudflare/vite-plugin`) and esbuild need no `?module` / `?init` suffix, `CompiledWasm` rule or plugin.

Budget: with `defaultProfile`, a hash costs ~19 MiB of the isolate's 128 MiB and tens of milliseconds of CPU. The wasm instance's linear memory grows to the largest `memoryCost` hashed or verified and stays at that size for the isolate's life, so hash one password per request and keep `defaultProfile` on Workers.

The [verify ceiling](#verify-ceiling) bounds what a stored hash can make that memory grow to. On Workers its default `maxMemoryKiB` is `65536` (64 MiB, half the isolate) rather than the general `131072`, which is the isolate's whole limit, so one verify at the ceiling cannot exhaust it; a configured `memoryCost` above 64 MiB raises it to that cost. Tighter is better: set `maxMemoryKiB` to the largest `memoryCost` you have ever written, which for a deployment that has only used `defaultProfile` is `19456`:

```ts
import { argon2HasherLayer } from "@thomasfosterau/effect-auth-argon2/Argon2";

const layer = argon2HasherLayer({ maxMemoryKiB: 19456 });
```

Raise it, before you raise `memoryCost`, to the new cost; never below a cost your stored hashes carry, or those users cannot sign in until they reset their password.

## Verification and parameter changes

`verify` reads the variant, cost parameters, salt and digest length out of the **stored** hash rather than assuming the configured ones. Raising your cost parameters (or moving from `defaultProfile` to `serverProfile`) therefore never locks anyone out — existing hashes keep verifying under the parameters they were written with.

### Verify ceiling

Because the costs come from the stored hash, a corrupt or attacker-written one (through a store-level compromise or a bring-your-own store bug) could demand gigabytes of memory or billions of iterations on the next sign-in. The wasm instance's memory never shrinks, so on Workers that would push the isolate past its 128 MiB and kill it, failing every request it serves. `verify` therefore refuses, with a `HashingError` and before the kernel runs, a stored hash whose costs exceed a ceiling:

| Option           | Default                                | Refuses a stored hash with |
| ---------------- | -------------------------------------- | -------------------------- |
| `maxMemoryKiB`   | `131072` (128 MiB); `65536` on Workers | `m` above it               |
| `maxIterations`  | `10`                                   | `t` above it               |
| `maxParallelism` | `8`                                    | `p` above it               |

The names and defaults match `@thomasfosterau/argon2`'s `verify(password, hash, { maxMemoryKiB, maxIterations, maxParallelism })`, except for the [lower `maxMemoryKiB` on Workers](#cloudflare-workers). The defaults sit above `serverProfile`, so every hash written with either profile verifies. Set them beside the costs:

```ts
import { argon2HasherLayer } from "@thomasfosterau/effect-auth-argon2/Argon2";

// Tighter on Workers: nothing this deployment wrote needs more than 19 MiB.
const layer = argon2HasherLayer({ maxMemoryKiB: 19456, maxIterations: 4, maxParallelism: 1 });
```

`verify` also refuses, the same way, a stored hash whose parameters repeat a name or add one other than `m`, `t` and `p` (so the ceiling always reads the costs the kernel would run), and one longer than 512 characters, before it is copied into wasm memory.

`argon2Hasher` and `argon2HasherLayer` throw a `RangeError` when a cost or a limit is not a positive integer, or when the configured costs exceed the ceiling (for example `memoryCost: 262144` without raising `maxMemoryKiB`), since such a hasher would write hashes its own `verify` refuses. Lowering the ceiling below costs your stored hashes already carry locks those users out until they reset their password, so lower it only to what you have written.

Hashes that cannot be recomputed (a malformed PHC string, an unsupported variant, Argon2 `v=0x10`, or a salt or digest outside the Argon2 crate's bounds: salt 8–48 bytes, digest 4–64 bytes) fail with a `HashingError` rather than silently returning `false`.

Every hash 0.1.x wrote with `hash-wasm` keeps verifying: the PHC format, the default parameters (`m=19456,t=2,p=1`, 16-byte salt, 32-byte digest) and the encoding are unchanged, and the tests verify `hash-wasm`-written fixtures for argon2id, argon2i and argon2d and check that the new backend derives byte-identical strings from the same salt.

### Rehashing

The hasher implements the core `PasswordHasher`'s `needsRehash`. It is true for a stored hash weaker than the configured costs (another variant such as `argon2i` or `argon2d`, a lower `m`, `t` or `p`, or a shorter salt or digest) and for one `verify` refuses. The core's sign-in flows (`EmailPasswordService.signIn`, username sign-in) call it after a successful verify and store a fresh hash, so after you raise the costs each user is moved to them on their next sign-in. A stored hash at least as strong in every parameter is kept; one weaker in any is replaced, even where it was stronger in another.

## Migrating from another hasher

`multiAlgorithmVerifier` routes by the algorithm segment of the stored hash, so Argon2id can be adopted alongside existing PBKDF2/scrypt hashes:

```ts
import { Password } from "@thomasfosterau/effect-auth";
import { argon2Hasher } from "@thomasfosterau/effect-auth-argon2/Argon2";

const verifier = Password.multiAlgorithmVerifier([argon2Hasher(), Password.pbkdf2Hasher()]);
```

Moving off this package onto the core hasher needs no migration: both write and read the same `$argon2id$v=19$…` strings, and the core's tests verify hashes this package wrote. Stored `argon2i` and `argon2d` hashes are the exception, since the core hasher reads only argon2id; keep this package in the verifier until they have been re-hashed.
