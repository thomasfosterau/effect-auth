# Provider expansion: per-provider TypeScript files

The ~35 social OAuth providers ship as individual TypeScript modules under
`packages/effect-auth/src/oauth/providers/`, each exporting a `<Provider>OAuth(config)` factory
that wraps the generic `makeOAuthProvider` with the provider's auth/token/userinfo URLs, default
scopes, profile-field mapping, and any provider-specific quirks. The four existing providers
(Google, GitHub, Discord, Microsoft) are the template.

The alternative — a data-driven registry where each provider is a config entry consumed by one
generic factory — was rejected because provider quirks are the norm, not the exception. Apple's
`id_token` comes back as a form-post not a query string; Twitter mandates PKCE; LinkedIn moved
userinfo from `/v2/me` to `/v2/userinfo` with different fields; Microsoft's tenant id changes
scope behaviour; Slack returns nested `team`/`enterprise` blocks; Spotify caps `state` length. A
registry forces an escape hatch for nearly every entry, which means we'd carry both a data layer
and per-provider code paths. Per-provider modules also let us express provider-specific config
(`AppleOAuth` requiring `teamId`/`keyId`) at the type level — the registry version would surface
those failures only at runtime.

Userinfo shapes are normalised to a common Schema (`id`, `email`, `emailVerified`, `name`,
`image`, plus a `raw` field for the untouched provider payload). The shape matches better-auth's
normalisation so deployments migrating in find a familiar mapping; the Schema typing is the
effect-auth-native part.

The cost is mechanical: 35 small files of ~50 lines each. To keep contribution cheap, a
`scaffold-provider` script (developer tool, not a library deliverable) generates the boilerplate
from a name + URLs + scope list, leaving the quirky bits to be hand-edited.
