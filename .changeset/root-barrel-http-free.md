---
"@thomasfosterau/effect-auth": minor
"@thomasfosterau/effect-auth-client": patch
---

**Breaking:** the package root no longer re-exports the HTTP tier as the `Http` namespace (#205). Importing `@thomasfosterau/effect-auth` for the headless core (sessions, users, stores, the authorization kernel) no longer pulls `effect/http-api` into your module graph; `ModuleGraph.test.ts` now asserts that.

The HTTP tier is unchanged and lives on the `./http` subpath. Migrate by importing it from there:

```ts
// before
import * as Auth from "@thomasfosterau/effect-auth";
const { handler } = Auth.Http.make({ services });

// after
import * as Http from "@thomasfosterau/effect-auth/http";
const { handler } = Http.make({ services });
```

`import { Http } from "@thomasfosterau/effect-auth"` becomes `import * as Http from "@thomasfosterau/effect-auth/http"`, and `import type { Http }` becomes `import type * as Http from "@thomasfosterau/effect-auth/http"`. Every name keeps its identity: `Http.ClientAddressConfigError`, `Http.ServicesBuildPendingError` and the rest are the same classes the root exports flat.

`effect-auth-client` now imports its wire types from `@thomasfosterau/effect-auth/http`; its own API is unchanged.
